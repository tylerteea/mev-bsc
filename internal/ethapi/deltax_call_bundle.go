package ethapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"
	"math"
	"math/big"
	"runtime/debug"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// CallBundleArgs represents the arguments for a call.
type CallBundleArgs struct {
	Txs                    []hexutil.Bytes       `json:"txs"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber"`
	Coinbase               *string               `json:"coinbase"`
	Timestamp              *uint64               `json:"timestamp"`
	Timeout                *int64                `json:"timeout"`
	GasLimit               *uint64               `json:"gasLimit"`
	Difficulty             *big.Int              `json:"difficulty"`
	SimulationLogs         bool                  `json:"simulationLogs"`
	StateOverrides         *StateOverride        `json:"stateOverrides"`
	BaseFee                *big.Int              `json:"baseFee"`
	ReqId                  string                `json:"reqId"`
}

// CallBundle will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *BundleAPI) CallBundle(ctx context.Context, args CallBundleArgs) (map[string]interface{}, error) {

	reqId := args.ReqId

	defer func() {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...callBundle", "err", r, "stack", dss, "reqId", reqId)
		}
	}()

	log.Info("callBundle_start", "reqId", reqId)

	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	var txs types.Transactions

	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)
	stateHead, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if stateHead == nil || err != nil {
		return nil, err
	}
	// 避免相互影响
	state := stateHead.Copy()

	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}
	blockNumber := big.NewInt(int64(args.BlockNumber))

	timestamp := parent.Time + 1
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = common.HexToAddress(*args.Coinbase)
	}
	difficulty := parent.Difficulty
	if args.Difficulty != nil {
		difficulty = args.Difficulty
	}
	gasLimit := parent.GasLimit
	if args.GasLimit != nil {
		gasLimit = *args.GasLimit
	}

	var baseFee *big.Int
	if args.BaseFee != nil {
		baseFee = args.BaseFee
	} else if s.b.ChainConfig().IsLondon(big.NewInt(args.BlockNumber.Int64())) {
		baseFee = eip1559.CalcBaseFee(s.b.ChainConfig(), parent)
	}

	header := &types.Header{
		ParentHash:    parent.Hash(),
		Number:        blockNumber,
		GasLimit:      gasLimit,
		Time:          timestamp,
		Difficulty:    difficulty,
		Coinbase:      coinbase,
		BaseFee:       baseFee,
		ExcessBlobGas: parent.ExcessBlobGas,
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	vmconfig := vm.Config{NoBaseFee: true}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	results := []map[string]interface{}{}

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), blockNumber, header.Time)
	var totalGasUsed uint64
	gasFees := new(big.Int)

	isPostMerge := header.Difficulty.Cmp(common.Big0) == 0
	rules := s.b.ChainConfig().Rules(header.Number, isPostMerge, header.Time)

	for _, tx := range txs {
		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		from, err := types.Sender(signer, tx)
		state.Prepare(rules, from, coinbase, tx.To(), vm.ActivePrecompiles(rules), tx.AccessList())

		receipt, result, err := ApplyTransactionWithResult(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		txHash := tx.Hash().String()

		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		to := "0x"
		if tx.To() != nil {
			to = tx.To().String()
		}
		jsonResult := map[string]interface{}{
			"txHash":      txHash,
			"gasUsed":     receipt.GasUsed,
			"fromAddress": from.String(),
			"toAddress":   to,
		}
		totalGasUsed += receipt.GasUsed

		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)

		// gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), tx.GasPrice())
		gasFees.Add(gasFees, gasFeesTx)
		bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			jsonResult[errorString] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				reason, _ := abi.UnpackRevert(revert)
				jsonResult["revert"] = reason
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			jsonResult["value"] = "0x" + string(dst)
		}
		// if simulation logs are requested append it to logs
		if args.SimulationLogs {
			jsonResult["logs"] = receipt.Logs
		}

		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["gasUsed"] = receipt.GasUsed
		results = append(results, jsonResult)
	}

	ret := map[string]interface{}{}

	ret["results"] = results
	ret["stateBlockNumber"] = header.Number.Int64()
	ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))

	//newResultJson, _ := json.Marshal(ret)
	//log.Info("call_bundle_result", "reqId", reqId, "ret", string(newResultJson))

	return ret, nil
}

// CallBundleCheckArgs represents the arguments for a call.
type CallBundleCheckArgs struct {
	Txs                    []hexutil.Bytes       `json:"txs"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber"`
	Coinbase               *string               `json:"coinbase"`
	Timestamp              *uint64               `json:"timestamp"`
	Timeout                *int64                `json:"timeout"`
	GasLimit               *uint64               `json:"gasLimit"`
	Difficulty             *big.Int              `json:"difficulty"`
	SimulationLogs         bool                  `json:"simulationLogs"`
	StateOverrides         *StateOverride        `json:"stateOverrides"`
	BaseFee                *big.Int              `json:"baseFee"`
	MevToken               common.Address        `json:"mevToken"`
	MevContract            common.Address        `json:"mevContract"`
	GrossProfit            *big.Int              `json:"grossProfit"`
	MinTokenOutBalance     *big.Int              `json:"minTokenOutBalance"`
	MevTokens              []common.Address      `json:"mevTokens"`
	ReqId                  string                `json:"reqId"`
}

// CallBundleCheckBalance will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *BundleAPI) CallBundleCheckBalance(ctx context.Context, args CallBundleCheckArgs) (map[string]interface{}, error) {

	reqId := args.ReqId

	defer func(start time.Time) {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...CallBundleCheckBalance", "err", r, "stack", dss, "reqId", reqId)
		}

		log.Info("CallBundleCheckBalance_end_defer", "reqId", reqId, "runtime", time.Since(start))
	}(time.Now())

	log.Info("CallBundleCheckBalance_0", "reqId", reqId)

	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}
	minTokenOutBalance := args.MinTokenOutBalance
	if minTokenOutBalance == nil {
		log.Info("minTokenOutBalance为空不允许执行", "reqId", reqId)
		return nil, errors.New("minTokenOutBalance is nil")
	}

	var txs types.Transactions

	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			log.Info("CallBundleCheckBalance_1", "reqId", reqId, "err", err)
			return nil, err
		}
		txs = append(txs, tx)
	}

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)
	stateHead, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if stateHead == nil || err != nil {
		return nil, err
	}
	// 避免相互影响
	state := stateHead.Copy()

	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}
	blockNumber := big.NewInt(int64(args.BlockNumber))

	timestamp := parent.Time + 1
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = common.HexToAddress(*args.Coinbase)
	}
	difficulty := parent.Difficulty
	if args.Difficulty != nil {
		difficulty = args.Difficulty
	}
	gasLimit := parent.GasLimit
	if args.GasLimit != nil {
		gasLimit = *args.GasLimit
	}

	var baseFee *big.Int
	if args.BaseFee != nil {
		baseFee = args.BaseFee
	} else if s.b.ChainConfig().IsLondon(big.NewInt(args.BlockNumber.Int64())) {
		baseFee = eip1559.CalcBaseFee(s.b.ChainConfig(), parent)
	}

	header := &types.Header{
		ParentHash:    parent.Hash(),
		Number:        blockNumber,
		GasLimit:      gasLimit,
		Time:          timestamp,
		Difficulty:    difficulty,
		Coinbase:      coinbase,
		BaseFee:       baseFee,
		ExcessBlobGas: parent.ExcessBlobGas,
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	vmconfig := vm.Config{NoBaseFee: true}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	results := []map[string]interface{}{}

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), blockNumber, header.Time)
	var totalGasUsed uint64
	gasFees := new(big.Int)

	isPostMerge := header.Difficulty.Cmp(common.Big0) == 0
	rules := s.b.ChainConfig().Rules(header.Number, isPostMerge, header.Time)

	//-------------------------------------------

	balancesBefore, err := getTokenBalanceByContract(ctx, s, args.MevTokens, args.MevContract, state, header)

	if err != nil {
		log.Info("call_bundle_balance_err1", "reqId", reqId, "err", err)
		return nil, err
	}

	if len(args.MevTokens) != len(balancesBefore) {
		log.Info("call_bundle_balance_err2", "reqId", reqId, "mevTokens_len", len(args.MevTokens), "balances_len", len(balancesBefore), "err", err)
		return nil, err
	}

	balancesBeforeMap := make(map[common.Address]*big.Int)

	for i, mevTokenTmp := range args.MevTokens {
		balancesBeforeMap[mevTokenTmp] = balancesBefore[i]
	}

	mainMevTokenBalance := balancesBeforeMap[args.MevToken]
	mainMevBalanceOriginal := new(big.Int).Sub(args.MinTokenOutBalance, args.GrossProfit)

	if mainMevTokenBalance.Cmp(mainMevBalanceOriginal) > 0 {
		minTokenOutBalance = new(big.Int).Add(mainMevTokenBalance, args.GrossProfit)
	}

	// 设置主mevToken 的余额限制为包含毛利的值
	balancesBeforeMap[args.MevToken] = minTokenOutBalance

	//-------------------------------------------

	for _, tx := range txs {

		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			log.Info("CallBundleCheckBalance_8", "reqId", reqId, "err", err)
			return nil, err
		}

		from, err := types.Sender(signer, tx)

		state.Prepare(rules, from, coinbase, tx.To(), vm.ActivePrecompiles(rules), tx.AccessList())

		receipt, result, err := ApplyTransactionWithResult(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
		if err != nil {
			log.Info("CallBundleCheckBalance_12", "reqId", reqId, "err", err)
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		if err != nil {
			log.Info("call_bundle_balance_err14", "reqId", reqId, "err", err)
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		to := "0x"
		if tx.To() != nil {
			to = tx.To().String()
		}
		jsonResult := map[string]interface{}{
			"txHash":      tx.Hash().String(),
			"gasUsed":     receipt.GasUsed,
			"fromAddress": from.String(),
			"toAddress":   to,
		}
		totalGasUsed += receipt.GasUsed

		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			log.Info("CallBundleCheckBalance_16", "reqId", reqId, "err", err)
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)

		// gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), tx.GasPrice())
		gasFees.Add(gasFees, gasFeesTx)
		bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			jsonResult[errorString] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				reason, _ := abi.UnpackRevert(revert)
				jsonResult["revert"] = reason
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			jsonResult["value"] = "0x" + string(dst)
		}
		// if simulation logs are requested append it to logs
		if args.SimulationLogs {
			jsonResult["logs"] = receipt.Logs
		}

		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["gasUsed"] = receipt.GasUsed
		results = append(results, jsonResult)
	}

	//-------------------------------------------

	balancesAfter, err := getTokenBalanceByContract(ctx, s, args.MevTokens, args.MevContract, state, header)

	if err != nil {
		log.Info("call_bundle_balance_err3", "reqId", reqId, "err", err)
		return nil, err
	}

	if len(args.MevTokens) != len(balancesAfter) {
		log.Info("call_bundle_balance_err4", "reqId", reqId, "mevTokens_len", len(args.MevTokens), "balances_len", len(balancesAfter), "err", err)
		return nil, err
	}

	balancesAfterMap := make(map[common.Address]*big.Int)

	for i, mevTokenTmp := range args.MevTokens {
		balancesAfterMap[mevTokenTmp] = balancesAfter[i]
	}

	isSuccess := true

	for address, balanceAfterTmp := range balancesAfterMap {
		balanceBeforeTmp := balancesBeforeMap[address]
		if balanceAfterTmp.Cmp(balanceBeforeTmp) < 0 {
			log.Info("call_bundle_balance校验失败", "reqId", reqId, "mevToken", address, "balanceBefore", balanceBeforeTmp.String(), "balanceAfter", balanceAfterTmp.String(), "err", err)
			isSuccess = false
		} else {
			log.Info("call_bundle_balance校验成功", "reqId", reqId, "mevToken", address, "balanceBefore", balanceBeforeTmp.String(), "balanceAfter", balanceAfterTmp.String(), "err", err)
		}
	}
	ret := map[string]interface{}{}

	checkResult := map[string]interface{}{}

	checkResult["balancesBefore"] = balancesBeforeMap
	checkResult["balancesAfter"] = balancesAfterMap

	ret["errMsg"] = ""
	ret["results"] = results
	ret["stateBlockNumber"] = header.Number.Int64()
	ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))

	if isSuccess {
		checkResult["check_balance"] = "success"
		log.Info("call_bundle_余额最终校验成功", "reqId", reqId)
	} else {

		ret["errMsg"] = "check_balance_fail"

		checkResult["check_balance"] = "fail"
		log.Info("call_bundle_余额最终校验失败", "reqId", reqId)
	}

	checkResultJson, _ := json.Marshal(checkResult)
	ret["check_result"] = string(checkResultJson)

	newResultJson, _ := json.Marshal(ret)
	log.Info("call_bundle_result_balance", "reqId", reqId, "ret", string(newResultJson))

	return ret, nil
}
