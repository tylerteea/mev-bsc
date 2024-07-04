package ethapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"math"
	"math/big"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/crypto/sha3"

	"gonum.org/v1/gonum/optimize"
)

const (
	V2 = int(2)
	V3 = int(3)

	frontAmountInString     = "frontAmountIn"
	frontAmountOutMidString = "frontAmountOutMid"
	frontAmountOutString    = "frontAmountOut"

	backAmountInString     = "backAmountIn"
	backAmountOutMidString = "backAmountOutMid"
	backAmountOutString    = "backAmountOut"

	profitString = "profit"
	errorString  = "error"
	reasonString = "reason"
)

var BigIntZeroValue = big.NewInt(0)
var epochNum = big.NewInt(200)
var delayBlockNum = big.NewInt(10)
var NullAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")

// --------------------------------------------------------Call Bundle--------------------------------------------------------

// BundleAPI offers an API for accepting bundled transactions
type BundleAPI struct {
	b     Backend
	chain *core.BlockChain
	bcapi *BlockChainAPI
}

// NewBundleAPI creates a new Tx Bundle API instance.
func NewBundleAPI(b Backend, chain *core.BlockChain) *BundleAPI {
	return &BundleAPI{b, chain, NewBlockChainAPI(b)}
}

func getTokenBalanceByContract(ctx context.Context, s *BundleAPI, tokens []common.Address, contractAddress common.Address, state *state.StateDB, header *types.Header) ([]*big.Int, error) {

	defer func() {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...getTokenBalanceByContract", "err", r, "stack", dss)
		}
	}()
	reqId := "getTokenBalanceByContract_"
	for _, token := range tokens {
		reqId += token.String() + "_"
	}
	reqId += contractAddress.String()

	inAddrType, _ := abi.NewType("address[]", "address[]", nil)
	inp := []abi.Argument{
		{
			Name: "tokens",
			Type: inAddrType,
		},
	}

	balanceType, _ := abi.NewType("uint256[]", "uint256[]", nil)
	oup := []abi.Argument{
		{
			Name: "memory",
			Type: balanceType,
		},
	}
	newMethod := abi.NewMethod("balancesOf", "balancesOf", abi.Function, "pure", false, false, inp, oup)
	pack, err := newMethod.Inputs.Pack(tokens)
	var data = append(newMethod.ID, pack...)
	bytes := (hexutil.Bytes)(data)

	callArgs := &TransactionArgs{
		To:   &contractAddress,
		Data: &bytes,
	}

	log.Info("call_getTokenBalance_start", "reqId", reqId, "data", common.Bytes2Hex(bytes))

	callResult, err := mevCall(reqId, state, header, s, ctx, callArgs, nil, nil, nil)

	log.Info("call_getTokenBalance1", "reqId", reqId)

	if callResult != nil {

		log.Info("call_getTokenBalance2", "reqId", reqId, "result", string(callResult.ReturnData))
		if len(callResult.Revert()) > 0 {

			revertReason := newRevertError(callResult.Revert())
			log.Info("call_getTokenBalance3",
				"reqId", reqId,
				"data", callResult,
				"revert", common.Bytes2Hex(callResult.Revert()),
				"revertReason", revertReason,
				"returnData", common.Bytes2Hex(callResult.Return()),
			)
			log.Info("call_getTokenBalance4", "reqId", reqId, "revertReason", revertReason.reason)
			return nil, revertReason
		}

		if callResult.Err != nil {
			log.Info("v", "reqId", reqId, "err", callResult.Err)
			return nil, callResult.Err
		}
	}
	if err != nil {
		log.Info("call_getTokenBalance5", "reqId", reqId, "err", err)
		return nil, err
	}

	unpack, err := newMethod.Outputs.Unpack(callResult.Return())
	if err != nil {
		log.Info("call_getTokenBalance_unpack_err", "reqId", reqId, "err", err)
		return nil, err
	}

	balances, ok := abi.ConvertType(unpack[0], []*big.Int{}).([]*big.Int)

	if ok {
		log.Info("call_getTokenBalance_ok", "reqId", reqId, "err", err)
		return balances, nil
	} else {
		log.Info("call_getTokenBalance_err", "reqId", reqId, "err", err)
		return nil, errors.New("转换失败")
	}
}

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

	defer func(start time.Time) {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...callBundle", "err", r, "stack", dss, "reqId", reqId)
		}

		log.Info("callBundle_end_defer", "reqId", reqId, "runtime", time.Since(start))
	}(time.Now())

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

		receipt, result, err := ApplyTransactionWithResultNew(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
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

	newResultJson, _ := json.Marshal(ret)
	log.Info("call_bundle_result", "reqId", reqId, "ret", string(newResultJson))
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

		receipt, result, err := ApplyTransactionWithResultNew(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
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
	if isSuccess {
		ret["errMsg"] = ""
		ret["results"] = results
		ret["stateBlockNumber"] = header.Number.Int64()
		ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))
		checkResult["check_balance"] = "success"
		checkResultJson, _ := json.Marshal(checkResult)
		ret["check_result"] = string(checkResultJson)

		newResultJson, _ := json.Marshal(ret)

		log.Info("call_bundle_result", "reqId", reqId, "ret", string(newResultJson))
		return ret, nil
	} else {

		ret["results"] = results
		ret["stateBlockNumber"] = header.Number.Int64()
		ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))

		checkResult["check_balance"] = "fail"
		checkResultJson, _ := json.Marshal(checkResult)
		ret["check_result"] = string(checkResultJson)

		newResultJson, _ := json.Marshal(ret)
		errMsg := string(newResultJson)
		ret["errMsg"] = errMsg

		log.Info("call_bundle_余额最终校验失败", "reqId", reqId, "ret", errMsg)
		return nil, errors.New(errMsg)
	}
}

//--------------------------------------------------------Multicall--------------------------------------------------------

// getCompactBlock returns the requested block, but only containing minimal information related to the block
// the logs in the block can also be requested
func (s *BlockChainAPI) GetCompactBlock(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash, logs bool) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumberOrHash(ctx, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	result := s.rpcMarshalCompactBlock(ctx, block)
	if logs { // add logs if requested
		receipts, err := s.b.GetReceipts(ctx, block.Hash())
		if err != nil {
			return nil, err
		}
		result["logs"] = s.rpcMarshalCompactLogs(ctx, receipts)
	}
	return result, nil
}

// multicall makes multiple eth_calls, on one state set by the provided block and overrides.
// returns an array of results [{data: 0x...}], and errors per call tx. the entire call fails if the requested state couldnt be found or overrides failed to be applied
func (s *BlockChainAPI) Multicall(ctx context.Context, txs []TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride) ([]map[string]interface{}, error) {
	results := []map[string]interface{}{}
	state, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := overrides.Apply(state); err != nil {
		return nil, err
	}
	for _, tx := range txs {
		thisState := state.Copy() // copy the state, because while eth_calls shouldnt change state, theres nothing stopping someobdy from making a state changing call
		results = append(results, DoSingleMulticall(ctx, s.b, tx, thisState, header, s.b.RPCEVMTimeout(), s.b.RPCGasCap()))
	}
	return results, nil
}

// single multicall makes a single call, given a header and state
// returns an object containing the return data, or error if one occured
// the result should be merged together later by multicall function
func DoSingleMulticall(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, timeout time.Duration, globalGasCap uint64) map[string]interface{} {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

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

	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	// Get a new instance of the EVM.
	msg, err := args.ToMessage(globalGasCap, header.BaseFee)
	if err != nil {
		return map[string]interface{}{
			errorString: err,
		}
	}

	evm := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	gopool.Submit(func() {
		<-ctx.Done()
		evm.Cancel()
	})

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := state.Error(); err != nil {
		return map[string]interface{}{
			errorString: err,
		}
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return map[string]interface{}{
			errorString: fmt.Errorf("execution aborted (timeout = %v)", timeout),
		}
	}
	if err != nil {
		return map[string]interface{}{
			errorString: fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit),
		}
	}
	if len(result.Revert()) > 0 {
		revertErr := newRevertError(result.Revert())
		data, _ := json.Marshal(&revertErr)
		var result map[string]interface{}
		json.Unmarshal(data, &result)
		return result
	}
	if result.Err != nil {
		return map[string]interface{}{
			errorString: "execution reverted",
		}
	}
	return map[string]interface{}{
		"data": hexutil.Bytes(result.Return()),
	}
}

// rpcMarshalCompact uses the generalized output filler, then adds the total difficulty field, which requires
// a `PublicBlockchainAPI`.
func (s *BlockChainAPI) rpcMarshalCompactBlock(ctx context.Context, b *types.Block) map[string]interface{} {
	return RPCMarshalCompactBlock(b)
}

// rpcMarshalCompact uses the generalized output filler, then adds the total difficulty field, which requires
// a `PublicBlockchainAPI`.
func (s *BlockChainAPI) rpcMarshalCompactLogs(ctx context.Context, r types.Receipts) []map[string]interface{} {
	return RPCMarshalCompactLogs(r)
}

func RPCMarshalCompactBlock(block *types.Block) map[string]interface{} {
	return map[string]interface{}{
		"number":     (*hexutil.Big)(block.Number()),
		"hash":       block.Hash(),
		"parentHash": block.ParentHash(),
	}
}

func RPCMarshalCompactLogs(receipts types.Receipts) []map[string]interface{} {
	logs := []map[string]interface{}{}
	for _, receipt := range receipts {
		for _, log := range receipt.Logs {
			logs = append(logs, map[string]interface{}{
				"address": log.Address,
				"data":    hexutil.Bytes(log.Data),
				"topics":  log.Topics,
			})
		}
	}
	return logs
}

func (s *BundleAPI) GetNowValidators(ctx context.Context, number *rpc.BlockNumber) map[string]interface{} {

	log.Info("GetValidators_start", "number", number)

	result := make(map[string]interface{})

	result[errorString] = "default"
	result[reasonString] = "default"

	log.Info("初始化parliaAPI", "number", number)

	var blockNum *big.Int
	header := s.chain.CurrentHeader()
	if number == nil || *number == rpc.LatestBlockNumber {
		blockNum = header.Number
	} else if header.Number.Cmp(big.NewInt(number.Int64())) < 0 {

		blockNum = big.NewInt(number.Int64())
		mod := new(big.Int).Mod(blockNum, epochNum)

		nowEpoch := new(big.Int).Sub(blockNum, mod)
		nowEpoch.Add(nowEpoch, delayBlockNum)

		if blockNum.Cmp(nowEpoch) >= 0 && header.Number.Cmp(nowEpoch) < 0 {
			result[errorString] = "blockNum_out_of_epoch_limit"
			result[reasonString] = "当前header属于上个epoch，但blockNum属于下个epoch,无法预测此种情况"
			result["number"] = blockNum
			return result
		}

		if new(big.Int).Sub(blockNum, header.Number).Cmp(epochNum) > 0 {
			result[errorString] = "blockNum_great_header_200"
			result[reasonString] = "请求的块号比最新header大200块"
			result["number"] = blockNum
			return result
		}
	} else {
		header = s.chain.GetHeaderByNumber(uint64(number.Int64()))
		blockNum = header.Number
	}

	result["number"] = blockNum

	if header == nil {
		result[errorString] = "header_nil"
		result[reasonString] = "header_nil"
		return result
	}

	validators, err := s.b.Engine().GetNowValidators(s.chain, header)
	if err == nil {
		result[errorString] = ""
		result[reasonString] = ""
		result["validators"] = validators
	} else {
		result[errorString] = err
		result[reasonString] = err
	}

	marshal, _ := json.Marshal(result)
	log.Info("打印validators", "number", number, "validators", string(marshal))
	return result
}

func (s *BundleAPI) GetBuilderNew(ctx context.Context, number *rpc.BlockNumber) map[string]interface{} {

	startTime := time.Now()

	log.Info("GetBuilder_start1", "number", number)

	result := make(map[string]interface{})

	result["number"] = number
	result[errorString] = "default"
	result[reasonString] = "default"

	validatorResult := s.GetNowValidators(ctx, number)

	if validatorResult == nil || validatorResult[errorString] != "" {
		return validatorResult
	}

	blockNum, ok := validatorResult["number"].(*big.Int)
	if !ok {
		result[errorString] = "number_err"
		result[reasonString] = "number_err"
		result["number"] = blockNum
		marshal, _ := json.Marshal(result)
		log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())
		return validatorResult
	}

	mod := new(big.Int).Mod(blockNum, epochNum)

	nowEpoch := new(big.Int).Sub(blockNum, mod)
	nowEpoch.Add(nowEpoch, delayBlockNum)

	// 如果大于等于10，则预测到下一个epoch截止，如果小于10则使用当前epoch当截止
	var targetEpoch *big.Int
	if blockNum.Cmp(nowEpoch) >= 0 {
		targetEpoch = new(big.Int).Add(nowEpoch, epochNum)
	} else if blockNum.Cmp(nowEpoch) < 0 {
		targetEpoch = nowEpoch
	}

	result["number"] = blockNum

	if targetEpoch == nil {
		result[errorString] = "targetEpoch_nil"
		result[reasonString] = "targetEpoch_nil"
	} else {
		builderMap := make(map[int64]interface{})
		for i := blockNum.Int64(); i < targetEpoch.Int64(); i++ {

			blockNumber := rpc.BlockNumber(i)

			validatorRes := s.GetNowValidators(ctx, &blockNumber)

			if validatorRes == nil || validatorRes[errorString] != "" {
				log.Info("找不到验证者1", "number", i)
				continue
			}
			validatorsTmp, ok1 := validatorRes["validators"].(common.Address)

			if !ok1 {
				log.Info("找不到验证者2", "number", i)
				continue
			}
			builderMap[i] = validatorsTmp
			log.Info("找到验证者", "number", i, "builder", validatorsTmp)
		}
		result[errorString] = ""
		result[reasonString] = ""
		result["builderMap"] = builderMap
	}
	marshal, _ := json.Marshal(result)
	log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())

	return result
}

func (s *BundleAPI) GetBuilder(ctx context.Context, number *rpc.BlockNumber) map[string]interface{} {

	startTime := time.Now()

	log.Info("GetBuilder_start1", "number", number)

	result := make(map[string]interface{})

	result["number"] = number
	result[errorString] = "default"
	result[reasonString] = "default"

	validatorResult := s.GetNowValidators(ctx, number)

	if validatorResult == nil || validatorResult[errorString] != "" {
		return validatorResult
	}
	validators, ok := validatorResult["validators"].([]common.Address)

	if !ok {
		result[errorString] = "validator_err"
		result[reasonString] = "validator_err"
		marshal, _ := json.Marshal(result)
		log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())
		return validatorResult
	}

	blockNum, ok := validatorResult["number"].(*big.Int)
	if !ok {
		result[errorString] = "number_err"
		result[reasonString] = "number_err"
		result["number"] = blockNum
		marshal, _ := json.Marshal(result)
		log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())
		return validatorResult
	}

	mod := new(big.Int).Mod(blockNum, epochNum)

	nowEpoch := new(big.Int).Sub(blockNum, mod)
	nowEpoch.Add(nowEpoch, delayBlockNum)

	// 如果大于等于10，则预测到下一个epoch截止，如果小于10则使用当前epoch当截止
	var targetEpoch *big.Int
	if blockNum.Cmp(nowEpoch) >= 0 {
		targetEpoch = new(big.Int).Add(nowEpoch, epochNum)
	} else if blockNum.Cmp(nowEpoch) < 0 {
		targetEpoch = nowEpoch
	}

	result["number"] = blockNum

	if targetEpoch == nil {
		result[errorString] = "targetEpoch_nil"
		result[reasonString] = "targetEpoch_nil"
	} else {
		builderMap := make(map[uint64]interface{})
		for i := blockNum.Uint64(); i < targetEpoch.Uint64(); i++ {
			offset := (i + 1) % uint64(len(validators))
			builderMap[i] = validators[offset]
		}
		result[errorString] = ""
		result[reasonString] = ""
		result["builderMap"] = builderMap
	}
	marshal, _ := json.Marshal(result)
	log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())

	return result
}

// SbpBuyArgs SandwichBestProfitArgs represents the arguments for a call.
type SbpBuyArgs struct {
	Eoa                common.Address `json:"eoa"`
	Contract           common.Address `json:"contract"`
	Balance            *big.Int       `json:"balance"`
	Token2             common.Address `json:"token2"`
	Token3             common.Address `json:"token3"`
	PairOrPool2        common.Address `json:"pairOrPool2"`
	ZeroForOne2        bool           `json:"zeroForOne2"`
	Fee2               *big.Int       `json:"fee2"`
	Version2           int            `json:"version2"`
	AmountInMin        *big.Int       `json:"amountInMin"`
	AmountOut          *big.Int       `json:"amountOut"`
	MinTokenOutBalance *big.Int       `json:"minTokenOutBalance"`
	BriberyAddress     common.Address `json:"briberyAddress"`
	VictimTxHash       common.Hash    `json:"vTxHash"`
	BuyOrSale          bool           `json:"buyOrSale"`
	SubOne             bool           `json:"subOne"`
	Token3BuyTax       bool           `json:"token3BuyTax"`
	Token3SaleTax      bool           `json:"token3SaleTax"`
	Steps              *big.Int       `json:"steps"`
	ReqId              string         `json:"reqId"`
	FuncEvaluations    int            `json:"funcEvaluations"`
	RunTimeout         int            `json:"runTimeout"`
	Iterations         int            `json:"iterations"`
	Concurrent         int            `json:"concurrent"`
	InitialValues      float64        `json:"initialValues"`
	LogEnable          bool           `json:"logEnable"`
}

type BuyConfig struct {
	Simulate      bool
	CheckTax      bool
	CalcAmountOut bool
	FeeToBuilder  bool
	ZeroForOne    bool
}

func NewBuyConfig(
	checkTax bool,
	calcAmountOut bool,
	feeToBuilder bool,
	zeroForOne bool,
) *BuyConfig {
	return &BuyConfig{
		Simulate:      true,
		CheckTax:      checkTax,
		CalcAmountOut: calcAmountOut,
		FeeToBuilder:  feeToBuilder,
		ZeroForOne:    zeroForOne,
	}
}

func buyConfigToBigInt(config *BuyConfig) *big.Int {
	configInt := int64(0)
	if config.Simulate {
		configInt += 16
	}
	if config.CheckTax {
		configInt += 8
	}
	if config.CalcAmountOut {
		configInt += 4
	}
	if config.FeeToBuilder {
		configInt += 2
	}
	if config.ZeroForOne {
		configInt += 1
	}
	return big.NewInt(configInt)
}

//--------------------------------------------------------------------------------

type SaleConfig struct {
	IsBackRun     bool
	Simulate      bool
	CheckTax      bool
	CalcAmountOut bool
	FeeToBuilder  bool
}

func NewSaleConfig(
	isBackRun bool,
	checkTax bool,
	calcAmountOut bool,
	feeToBuilder bool,
) *SaleConfig {
	return &SaleConfig{
		IsBackRun:     isBackRun,
		Simulate:      true,
		CheckTax:      checkTax,
		CalcAmountOut: calcAmountOut,
		FeeToBuilder:  feeToBuilder,
	}
}

func saleConfigToBigInt(config *SaleConfig) *big.Int {
	configInt := int64(0)
	if config.IsBackRun {
		configInt += 32
	}
	if config.Simulate {
		configInt += 16
	}
	if config.CheckTax {
		configInt += 8
	}
	if config.CalcAmountOut {
		configInt += 4
	}
	if config.FeeToBuilder {
		configInt += 2
	}
	return big.NewInt(configInt)
}

//==============================

type SaleOption struct {
	ZeroForOne2  bool
	Version2IsV3 bool
	ZeroForOne1  bool
	Version1IsV3 bool
}

func NewSaleOption(
	zeroForOne2 bool,
	version2IsV3 bool,
	zeroForOne1 bool,
	version1IsV3 bool,
) *SaleOption {
	return &SaleOption{
		ZeroForOne2:  zeroForOne2,
		Version2IsV3: version2IsV3,
		ZeroForOne1:  zeroForOne1,
		Version1IsV3: version1IsV3,
	}
}

func saleOptionToBigInt(config *SaleOption) *big.Int {
	configInt := int64(0)
	if config.ZeroForOne2 {
		configInt += 8
	}
	if config.Version2IsV3 {
		configInt += 4
	}
	if config.ZeroForOne1 {
		configInt += 2
	}
	if config.Version1IsV3 {
		configInt += 1
	}
	return big.NewInt(configInt)
}

//------------------------------------------------------------------------------------------

type SbpSaleArgs struct {
	Eoa      common.Address `json:"eoa"`
	Contract common.Address `json:"contract"`
	Balance  *big.Int       `json:"balance"`

	Token1        common.Address `json:"token1"`
	Token2        common.Address `json:"token2"`
	Token3        common.Address `json:"token3"`
	PairOrPool1   common.Address `json:"pairOrPool1"`
	ZeroForOne1   bool           `json:"zeroForOne1"`
	Fee1          *big.Int       `json:"fee1"`
	Version1      int            `json:"version1"`
	PairOrPool2   common.Address `json:"pairOrPool2"`
	ZeroForOne2   bool           `json:"zeroForOne2"`
	Fee2          *big.Int       `json:"fee2"`
	Version2      int            `json:"version2"`
	BuyOrSale     bool           `json:"buyOrSale"`
	SubOne        bool           `json:"subOne"`
	Token3BuyTax  bool           `json:"token3BuyTax"`
	Token3SaleTax bool           `json:"token3SaleTax"`

	AmountInMin        *big.Int       `json:"amountInMin"`
	MinTokenOutBalance *big.Int       `json:"minTokenOutBalance"`
	BriberyAddress     common.Address `json:"briberyAddress"`
	VictimTxHash       common.Hash    `json:"vTxHash"`
	Steps              *big.Int       `json:"steps"`
	ReqId              string         `json:"reqId"`
	FuncEvaluations    int            `json:"funcEvaluations"`
	RunTimeout         int            `json:"runTimeout"`
	Iterations         int            `json:"iterations"`
	Concurrent         int            `json:"concurrent"`
	InitialValues      float64        `json:"initialValues"`
	LogEnable          bool           `json:"logEnable"`
}

// SandwichBestProfitMinimizeBuy profit calculate
func (s *BundleAPI) SandwichBestProfitMinimizeBuy(ctx context.Context, sbp SbpBuyArgs) map[string]interface{} {

	sbpSaleArgs := SbpSaleArgs{
		Eoa:                sbp.Eoa,
		Contract:           sbp.Contract,
		Balance:            sbp.Balance,
		Token1:             common.Address{},
		Token2:             sbp.Token2,
		Token3:             sbp.Token3,
		PairOrPool1:        common.Address{},
		ZeroForOne1:        false,
		Fee1:               nil,
		Version1:           0,
		PairOrPool2:        sbp.PairOrPool2,
		ZeroForOne2:        sbp.ZeroForOne2,
		Fee2:               sbp.Fee2,
		Version2:           sbp.Version2,
		AmountInMin:        sbp.AmountInMin,
		MinTokenOutBalance: sbp.MinTokenOutBalance,
		BriberyAddress:     sbp.BriberyAddress,
		VictimTxHash:       sbp.VictimTxHash,
		BuyOrSale:          sbp.BuyOrSale,
		SubOne:             sbp.SubOne,
		Token3BuyTax:       sbp.Token3BuyTax,
		Token3SaleTax:      sbp.Token3SaleTax,
		Steps:              sbp.Steps,
		ReqId:              sbp.ReqId,
		FuncEvaluations:    sbp.FuncEvaluations,
		RunTimeout:         sbp.RunTimeout,
		Iterations:         sbp.Iterations,
		Concurrent:         sbp.Concurrent,
		InitialValues:      sbp.InitialValues,
		LogEnable:          sbp.LogEnable,
	}

	return s.SandwichBestProfitMinimizeSale(ctx, sbpSaleArgs)
}

// SandwichBestProfitMinimizeSale profit calculate
func (s *BundleAPI) SandwichBestProfitMinimizeSale(ctx context.Context, sbp SbpSaleArgs) map[string]interface{} {

	result := make(map[string]interface{})

	result[errorString] = "default"
	result[reasonString] = "default"

	now := time.Now()
	um := now.UnixMilli()

	var reqId string
	if sbp.ReqId != "" {
		reqId = sbp.ReqId
	} else {
		reqId = strconv.FormatInt(um, 10)
	}

	defer timeCost(reqId, now)

	if sbp.LogEnable {
		req, _ := json.Marshal(sbp)
		log.Info("call_sbp_start", "reqId", reqId, "sbp", string(req))
	}

	timeout := s.b.RPCEVMTimeout()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	defer cancel()
	defer func(results *map[string]interface{}) {
		if r := recover(); r != nil {
			if sbp.LogEnable {
				oldResultJson, _ := json.Marshal(result)
				log.Info("call_sbp_old_result_", "reqId", reqId, "result", string(oldResultJson))
			}
			result[errorString] = "panic"
			result[reasonString] = r
			if sbp.LogEnable {
				newResultJson, _ := json.Marshal(result)
				log.Info("call_sbp_defer_result_", "reqId", reqId, "result", string(newResultJson))
			}
		}
	}(&result)

	if sbp.Balance.Cmp(big.NewInt(0)) == 0 {
		result[errorString] = "args_err"
		result[reasonString] = "balance_is_0"
		return result
	}
	balance := sbp.Balance

	minAmountIn := sbp.AmountInMin
	victimTxHash := sbp.VictimTxHash

	// 根据受害人tx hash  从内存池得到tx msg
	victimTransaction := s.b.GetPoolTransaction(victimTxHash)

	// 获取不到 直接返回
	if victimTransaction == nil {
		result[errorString] = "tx_is_nil"
		result[reasonString] = "GetPoolTransaction and GetTransaction all nil : " + victimTxHash.Hex()
		if sbp.LogEnable {
			resultJson, _ := json.Marshal(result)
			log.Info("call_sbp_2_", "reqId", reqId, "result", string(resultJson))
		}
		return result
	}

	number := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	stateDBNew, head, _ := s.b.StateAndHeaderByNumberOrHash(ctx, number)

	if sbp.LogEnable {
		log.Info("call_sbp_4_", "reqId", reqId, "blockNumber", number.BlockNumber.Int64(), "number", head.Number, "hash", head.Hash(), "parentHash", head.ParentHash)
	}
	pow1018 := math.Pow10(18)

	var bestInFunc = func(x []float64) float64 { return 0 }

	bestInFunc = func(x []float64) float64 {
		defer func() {
			if err := recover(); err != nil {
				log.Error(fmt.Sprintf("call_sandwichBestProfitMinimize_bestInFunc x[0]:%v, err:%v", x[0], err))
			}
		}()

		amountInFloat := x[0]
		if sbp.LogEnable {
			log.Info("call_sbp_5", "reqId", reqId, "amountInFloat", amountInFloat)
		}
		if amountInFloat < 0 {
			if sbp.LogEnable {
				log.Info("call_sbp_6", "reqId", reqId, "amountInFloat", amountInFloat)
			}
			return 0.0
		}
		if sbp.LogEnable {
			log.Info("call_sbp_7", "reqId", reqId, "amountInFloat", amountInFloat)
		}
		amountIn := new(big.Float).Mul(big.NewFloat(amountInFloat), big.NewFloat(pow1018))

		amountInInt := new(big.Int)
		amountIn.Int(amountInInt)

		f, _ := amountIn.Float64()

		if amountInInt.Cmp(balance) > 0 {
			if sbp.LogEnable {
				log.Info("call_sbp_8", "reqId", reqId, "amountInFloat", amountInFloat)
			}
			return f
		}

		if amountInInt.Cmp(minAmountIn) < 0 {
			if sbp.LogEnable {
				log.Info("call_sbp_9", "reqId", reqId, "amountInFloat", amountInFloat)
			}
			return 0.0
		}

		startTime := time.Now()
		stateDB := stateDBNew.Copy()
		workerResults := worker(ctx, head, victimTransaction, sbp, s, reqId, stateDB, amountInInt)
		costTime := time.Since(startTime).Milliseconds()

		if sbp.LogEnable {
			log.Info("call_sbp_99", "reqId", reqId, "amountInFloat", amountInFloat, "cost_time", costTime)
		}

		reqIdMiniMize := reqId + amountInInt.String()

		if sbp.LogEnable {
			marshal, _ := json.Marshal(workerResults)
			log.Info("call_worker_minimize_result_end", "reqId", reqIdMiniMize, "amountIn", amountInInt, "result", string(marshal))
		}
		if workerResults[errorString] == nil && workerResults[profitString] != nil {
			profit, ok := workerResults[profitString].(*big.Int)
			//if ok && profit > 0 {
			if ok { // 让函数能够感知负值
				if sbp.LogEnable {
					log.Info("call_sbp_10", "reqId", reqId, "amountInFloat", amountInFloat)
				}
				profitFloat, _ := new(big.Float).SetInt(profit).Float64()
				return 0.0 - profitFloat
			}
			if sbp.LogEnable {
				log.Info("call_sbp_11", "reqId", reqId, "amountInFloat", amountInFloat)
			}
		}
		if sbp.LogEnable {
			log.Info("call_sbp_12", "reqId", reqId, "amountInFloat", amountInFloat)
		}
		return f
	}

	p := optimize.Problem{
		Func: bestInFunc,
	}

	var meth = &optimize.NelderMead{}     // 下山单纯形法
	var p0 = []float64{sbp.InitialValues} // initial value for mu

	var initValues = &optimize.Location{X: p0}

	settings := &optimize.Settings{
		FuncEvaluations: sbp.FuncEvaluations,
		Runtime:         time.Duration(sbp.RunTimeout * 1000 * 1000),
		Concurrent:      sbp.Concurrent,
	}

	settings.Converger = &optimize.FunctionConverge{
		Absolute:   1e32,
		Relative:   1e32,
		Iterations: sbp.Iterations,
	}

	res, err := optimize.Minimize(p, initValues.X, settings, meth)

	if sbp.LogEnable {
		resJson, _ := json.Marshal(res)
		log.Info("call_sbp_minimize_result", "reqId", reqId, "result", string(resJson))
	}

	resJson, _ := json.Marshal(res)
	log.Info("call_sbp_minimize_result", "reqId", reqId, "result", string(resJson))

	if err != nil {
		result[errorString] = "minimize_err"
		result[reasonString] = err.Error()
		if sbp.LogEnable {
			resultJson, _ := json.Marshal(result)
			log.Info("call_sbp_minimize_err", "reqId", reqId, "result", string(resultJson))
		}
		return result
	}

	x := res.X[0]
	maxProfitAmountIn := big.NewFloat(0).Mul(big.NewFloat(x), big.NewFloat(pow1018))
	quoteAmountIn := new(big.Int)
	maxProfitAmountIn.Int(quoteAmountIn)

	if quoteAmountIn.Cmp(balance) > 0 || quoteAmountIn.Cmp(minAmountIn) < 0 {
		result[errorString] = "minimize_result_out_of_limit"
		result[reasonString] = quoteAmountIn
		if sbp.LogEnable {
			resultJson, _ := json.Marshal(result)
			log.Info("call_sbp_minimize_out_of_limit", "reqId", reqId, "result", string(resultJson))
		}
		return result
	}

	reqAndIndex := reqId + "_end"

	sdb := stateDBNew.Copy()
	workerResults := worker(ctx, head, victimTransaction, sbp, s, reqAndIndex, sdb, quoteAmountIn)

	if sbp.LogEnable {
		marshal, _ := json.Marshal(workerResults)
		log.Info("call_worker_result_end", "reqId", reqAndIndex, "amountInReal", quoteAmountIn, "result", string(marshal))
	}

	if workerResults[errorString] == nil && workerResults[profitString] != nil {
		profit, ok := workerResults[profitString].(*big.Int)
		if ok && profit.Cmp(big.NewInt(0)) > 0 {
			result = workerResults
		}
	}
	if sbp.LogEnable {
		resultJson, _ := json.Marshal(result)
		log.Info("call_sbp_end", "reqId", reqId, "blockNumber", number.BlockNumber.Int64(), "result", string(resultJson), "cost_time(ms)", time.Since(now).Milliseconds())
	}
	return result
}

func worker(
	ctx context.Context,
	head *types.Header,
	victimTransaction *types.Transaction,
	sbp SbpSaleArgs,
	s *BundleAPI,
	reqAndIndex string,
	statedb *state.StateDB,
	amountIn *big.Int) map[string]interface{} {

	defer func() {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...call_SandwichBestProfit", "reqAndIndex", reqAndIndex, "err", r, "stack", dss)
		}
	}()

	result := make(map[string]interface{})

	// 抢跑----------------------------------------------------------------------------------------
	startTime := time.Now()
	frontAmountOutMid, frontAmountOut, fErr := execute(ctx, reqAndIndex, true, sbp, amountIn, statedb, s, head)
	costTime := time.Since(startTime).Milliseconds()

	if sbp.LogEnable {
		log.Info("call_execute_front", "reqAndIndex", reqAndIndex, "amountIn", amountIn, frontAmountOutMidString, frontAmountOutMid, frontAmountInString, frontAmountOut, "fErr", fErr, "cost_time", costTime)
	}
	if fErr != nil {
		result[errorString] = "frontCallErr"
		result[reasonString] = fErr.Error()
		result[frontAmountInString] = amountIn.String()
		return result
	}

	backAmountIn := frontAmountOut
	if sbp.SubOne {
		backAmountIn = new(big.Int).Sub(frontAmountOut, big.NewInt(1))
	}

	if backAmountIn.Cmp(big.NewInt(0)) <= 0 {
		result[errorString] = "backAmountInZero"
		result[reasonString] = "backAmountInZero"
		result[frontAmountInString] = amountIn.String()
		return result
	}

	if !sbp.BuyOrSale {
		if frontAmountOutMid.Cmp(big.NewInt(0)) <= 0 {
			result[errorString] = "frontAmountOutMid_Zero"
			result[reasonString] = "frontAmountOutMid_Zero"
			result[frontAmountInString] = amountIn.String()
			return result
		}
	}

	// 受害者----------------------------------------------------------------------------------------
	victimStartTime := time.Now()
	victimTxMsg, victimTxMsgErr := core.TransactionToMessage(victimTransaction, types.MakeSigner(s.b.ChainConfig(), head.Number, head.Time), head.BaseFee)

	if victimTxMsgErr != nil {
		result[errorString] = "victimTxMsgErr"
		result[reasonString] = victimTxMsgErr
		return result
	}

	evmContext := core.NewEVMBlockContext(head, s.chain, nil)
	victimTxContext := core.NewEVMTxContext(victimTxMsg)

	vmEnv := vm.NewEVM(evmContext, victimTxContext, statedb, s.chain.Config(), vm.Config{NoBaseFee: true})
	err := gopool.Submit(func() {
		<-ctx.Done()
		vmEnv.Cancel()
	})
	if err != nil {
		result[errorString] = "victimPoolSubmit"
		result[reasonString] = err.Error()
		return result
	}
	gasPool := new(core.GasPool).AddGas(math.MaxUint64)
	victimTxCallResult, victimTxCallErr := core.ApplyMessage(vmEnv, victimTxMsg, gasPool)

	victimCostTime := time.Since(victimStartTime).Milliseconds()

	if sbp.LogEnable {
		log.Info("call_execute_victim", "reqAndIndex", reqAndIndex, "cost_time", victimCostTime)
	}

	if victimTxCallErr != nil {
		result[errorString] = "victimTxCallErr"
		result[reasonString] = victimTxCallErr.Error()
		result[frontAmountInString] = amountIn.String()
		return result
	}
	if len(victimTxCallResult.Revert()) > 0 {
		result[errorString] = "execution_victimTx_reverted"
		result[reasonString] = victimTxCallResult.Err.Error()
		result[frontAmountInString] = amountIn.String()
		return result
	}
	if victimTxCallResult.Err != nil {
		result[errorString] = "execution_victimTx_callResult_err"
		result[reasonString] = victimTxCallResult.Err.Error()
		result[frontAmountInString] = amountIn.String()
		return result
	}

	// 跟跑----------------------------------------------------------------------------------------
	backStartTime := time.Now()
	backAmountOutMid, backAmountOut, bErr := execute(ctx, reqAndIndex, false, sbp, backAmountIn, statedb, s, head)
	backCostTime := time.Since(backStartTime).Milliseconds()

	if sbp.LogEnable {
		log.Info("call_execute_back", "reqAndIndex", reqAndIndex, backAmountInString, backAmountIn, backAmountOutMidString, backAmountOutMid, backAmountOutString, backAmountOut, "bErr", bErr, "cost_time", backCostTime)
	}
	if bErr != nil || backAmountOut.Cmp(big.NewInt(0)) <= 0 {
		result[errorString] = "backCallErr"
		result[reasonString] = bErr.Error()
		result[frontAmountInString] = amountIn
		result[frontAmountOutMidString] = frontAmountOutMid
		result[frontAmountInString] = frontAmountOut
		result[backAmountInString] = backAmountIn
		result[backAmountOutMidString] = backAmountOutMid
		result[backAmountOutString] = backAmountOut
		return result
	}

	if !sbp.BuyOrSale {
		if backAmountOutMid.Cmp(big.NewInt(0)) <= 0 {
			result[errorString] = "backCallErr1"
			result[reasonString] = "backAmountOutMid_zero"
			result[frontAmountInString] = amountIn
			result[frontAmountOutMidString] = frontAmountOutMid
			result[frontAmountOutString] = frontAmountOut
			result[backAmountInString] = backAmountIn
			result[backAmountOutMidString] = backAmountOutMid
			result[backAmountOutString] = backAmountOut
			return result
		}
	}

	profit := new(big.Int).Sub(backAmountOut, amountIn)

	result[frontAmountInString] = amountIn
	result[frontAmountOutString] = frontAmountOut
	result[frontAmountOutMidString] = frontAmountOutMid
	result[backAmountInString] = backAmountIn
	result[backAmountOutMidString] = backAmountOutMid
	result[backAmountOutString] = backAmountOut
	result[profitString] = profit

	if profit.Cmp(big.NewInt(0)) <= 0 {
		result[errorString] = "profit_too_low"
		result[reasonString] = errors.New("profit_too_low")
	}

	endTime := time.Since(startTime).Milliseconds()

	if sbp.LogEnable {
		log.Info("call_execute_finish", "reqAndIndex", reqAndIndex, "cost_time", endTime)
	}
	return result
}

func execute(
	ctx context.Context,
	reqId string,
	isFront bool,
	sbp SbpSaleArgs,
	amountIn *big.Int,
	sdb *state.StateDB,
	s *BundleAPI,
	head *types.Header) (*big.Int, *big.Int, error) {

	var data []byte

	if sbp.LogEnable {
		log.Info("call_execute1", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}
	if isFront {

		if sbp.BuyOrSale {

			// 模拟的时候都检查税，正式发不检查
			frontBuyConfig := NewBuyConfig(true, true, false, sbp.ZeroForOne2)
			frontMinTokenOutBalance := big.NewInt(0)
			data = encodeParamsBuy(sbp.Version2, true, amountIn, sbp.PairOrPool2, sbp.Token2, sbp.Token3, frontBuyConfig, sbp.Fee2, BigIntZeroValue, frontMinTokenOutBalance, sbp.BriberyAddress)
		} else {

			// 模拟的时候都检查税，正式发不检查
			frontSaleConfig := NewSaleConfig(!isFront, true, true, false)
			frontSaleOption := NewSaleOption(sbp.ZeroForOne2, sbp.Version2 == V3, sbp.ZeroForOne1, sbp.Version1 == V3)

			data = encodeParamsSale(amountIn, sbp.PairOrPool1, sbp.PairOrPool2, sbp.Token1, sbp.Token2, sbp.Token3, frontSaleOption, frontSaleConfig, sbp.Fee1, sbp.Fee2, BigIntZeroValue, BigIntZeroValue, sbp.MinTokenOutBalance, sbp.BriberyAddress)
		}

	} else {

		if sbp.BuyOrSale {

			// 模拟的时候都检查税，正式发不检查
			backBuyConfig := NewBuyConfig(true, true, false, !sbp.ZeroForOne2)
			data = encodeParamsBuy(sbp.Version2, false, amountIn, sbp.PairOrPool2, sbp.Token3, sbp.Token2, backBuyConfig, sbp.Fee2, BigIntZeroValue, sbp.MinTokenOutBalance, sbp.BriberyAddress)
		} else {

			// 模拟的时候都检查税，正式发不检查
			backSaleConfig := NewSaleConfig(!isFront, true, true, false)
			backSaleOption := NewSaleOption(!sbp.ZeroForOne1, sbp.Version1 == V3, !sbp.ZeroForOne2, sbp.Version2 == V3)

			data = encodeParamsSale(amountIn, sbp.PairOrPool2, sbp.PairOrPool1, sbp.Token3, sbp.Token2, sbp.Token1, backSaleOption, backSaleConfig, sbp.Fee2, sbp.Fee1, BigIntZeroValue, BigIntZeroValue, sbp.MinTokenOutBalance, sbp.BriberyAddress)
		}
	}

	if sbp.LogEnable {
		log.Info("call_execute2", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "data_hex", common.Bytes2Hex(data))
	}
	bytes := hexutil.Bytes(data)
	callArgs := &TransactionArgs{
		From: &sbp.Eoa,
		To:   &sbp.Contract,
		Data: &bytes,
	}

	reqIdString := reqId + amountIn.String()

	callResult, err := mevCall(reqIdString, sdb, head, s, ctx, callArgs, nil, nil, nil)
	if sbp.LogEnable {
		log.Info("call_execute3", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", err, "callResult", callResult)
	}
	if callResult != nil {

		if sbp.LogEnable {
			log.Info("call_execute4", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "result", string(callResult.ReturnData))
		}
		var revertReason *revertError
		if len(callResult.Revert()) > 0 {

			revertReason = newRevertError(callResult.Revert())
			if sbp.LogEnable {
				log.Info("call_result_not_nil_44",
					"reqId", reqId,
					"amountIn", amountIn,
					"data", callResult,
					"revert", common.Bytes2Hex(callResult.Revert()),
					"revertReason", revertReason,
					"returnData", common.Bytes2Hex(callResult.Return()),
				)
				log.Info("call_execute5", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "revertReason", revertReason.reason)
			}
			return nil, nil, revertReason
		}
	}
	if err != nil {
		if sbp.LogEnable {
			log.Info("call_execute6", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", err)
		}
		return nil, nil, err
	}
	if callResult.Err != nil {
		if sbp.LogEnable {
			log.Info("call_execute7", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", callResult.Err)
		}
		return nil, nil, callResult.Err
	}

	lenR := len(callResult.Return())
	if sbp.LogEnable {
		log.Info("call_execute80_结果数据长度", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR)
	}
	amountOutMid := big.NewInt(0)
	amountOut := big.NewInt(0)

	if sbp.BuyOrSale {
		if lenR == 32 {
			amountOut = new(big.Int).SetBytes(callResult.Return())
			if amountOut.Cmp(big.NewInt(0)) <= 0 {
				if sbp.LogEnable {
					log.Info("call_execute8_买结果数据大小检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR, "amountOutMid", amountOutMid.String(), "amountOut", amountOut.String())
				}
				return nil, nil, errors.New("买结果数据大小检验不通过1")
			}

		} else {
			if sbp.LogEnable {
				log.Info("call_execute9_买结果数据大小检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR, "amountOutMid", amountOutMid.String(), "amountOut", amountOut.String())
			}
			return nil, nil, errors.New("买结果数据长度检验不通过2")
		}
	} else {

		if lenR == 64 {
			amountOutMid = new(big.Int).SetBytes(callResult.Return()[:32])
			amountOut = new(big.Int).SetBytes(callResult.Return()[32:64])
			if amountOutMid.Cmp(big.NewInt(0)) <= 0 || amountOut.Cmp(big.NewInt(0)) <= 0 {
				if sbp.LogEnable {
					log.Info("call_execute10_卖结果数据大小检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR, "amountOutMid", amountOutMid.String(), "amountOut", amountOut.String())
				}
				return nil, nil, errors.New("卖结果数据大小检验不通过1")
			}
		} else {
			if sbp.LogEnable {
				log.Info("call_execute11_卖结果数据长度检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR, "amountOutMid", amountOutMid.String(), "amountOut", amountOut.String())
			}
			return nil, nil, errors.New("卖结果数据长度检验不通过2")
		}
	}
	if sbp.LogEnable {
		log.Info("call_execute20", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "amountOutMid", amountOutMid.String(), "amountOut", amountOut.String())
	}
	return amountOutMid, amountOut, nil
}

// execute_44g58pv
func encodeParamsSale(
	amountIn *big.Int,

	pairOrPool1 common.Address,
	pairOrPool2 common.Address,

	token1 common.Address,
	token2 common.Address,
	token3 common.Address,

	option *SaleOption,
	config *SaleConfig,

	fee1 *big.Int,
	fee2 *big.Int,

	amountOut1 *big.Int,
	amountOut2 *big.Int,

	minTokenOutBalance *big.Int,
	builderAddress common.Address,
) []byte {
	params := make([]byte, 0)
	params = append(params, []byte{0x00, 0x00, 0x00, 0x00}...)

	params = append(params, fillBytes(14, amountIn.Bytes())...)

	params = append(params, pairOrPool1.Bytes()...)
	params = append(params, pairOrPool2.Bytes()...)

	params = append(params, token1.Bytes()...)
	params = append(params, token2.Bytes()...)
	params = append(params, token3.Bytes()...)

	params = append(params, fillBytes(1, saleOptionToBigInt(option).Bytes())...)
	params = append(params, fillBytes(1, saleConfigToBigInt(config).Bytes())...)

	if config.CalcAmountOut {
		if !option.Version1IsV3 {
			params = append(params, fillBytes(2, fee1.Bytes())...)
		}
		if !option.Version2IsV3 {
			params = append(params, fillBytes(2, fee2.Bytes())...)
		}
	} else {
		if !option.Version1IsV3 {
			params = append(params, fillBytes(14, amountOut1.Bytes())...)
		}
		if !option.Version2IsV3 {
			params = append(params, fillBytes(14, amountOut2.Bytes())...)
		}
	}

	if config.IsBackRun {
		params = append(params, fillBytes(14, minTokenOutBalance.Bytes())...)
		if builderAddress.Cmp(NullAddress) != 0 {
			params = append(params, builderAddress.Bytes()...)
		}
	}
	return params
}

func encodeParamsBuy(
	version int,
	isFront bool,
	amountIn *big.Int,
	pairOrPool common.Address,
	tokenIn common.Address,
	tokenOut common.Address,
	config *BuyConfig,
	fee *big.Int,
	amountOut *big.Int,
	minTokenOutBalance *big.Int,
	builderAddress common.Address,
) []byte {

	if version == V2 {
		if isFront {
			return v2BuyFrontEncodeParams(amountIn, pairOrPool, tokenIn, tokenOut, config, fee, amountOut)
		} else {
			return v2BuyBackEncodeParams(amountIn, pairOrPool, tokenIn, tokenOut, config, fee, amountOut, minTokenOutBalance, builderAddress)
		}
	} else {
		if isFront {
			return v3BuyFrontEncodeParams(amountIn, pairOrPool, tokenIn, tokenOut, config)
		} else {
			return v3BuyBackEncodeParams(amountIn, pairOrPool, tokenIn, tokenOut, config, minTokenOutBalance, builderAddress)
		}
	}
}

func v2BuyFrontEncodeParams(
	amountIn *big.Int,
	pair common.Address,
	tokenIn common.Address,
	tokenOut common.Address,
	config *BuyConfig,
	fee *big.Int,
	amountOut *big.Int,
) []byte {
	params := make([]byte, 0)
	params = append(params, []byte{0x00, 0x00, 0x00, 0x01}...)

	params = append(params, fillBytes(14, amountIn.Bytes())...)
	params = append(params, pair.Bytes()...)
	params = append(params, tokenIn.Bytes()...)
	params = append(params, tokenOut.Bytes()...)

	params = append(params, fillBytes(1, buyConfigToBigInt(config).Bytes())...)

	if config.CalcAmountOut {
		params = append(params, fillBytes(2, fee.Bytes())...)
	} else {
		params = append(params, fillBytes(14, amountOut.Bytes())...)
	}

	return params
}

func v2BuyBackEncodeParams(
	amountIn *big.Int,
	pair common.Address,
	tokenIn common.Address,
	tokenOut common.Address,
	config *BuyConfig,
	fee *big.Int,
	amountOut *big.Int,
	minTokenOutBalance *big.Int,
	builderAddress common.Address,
) []byte {
	params := make([]byte, 0)
	params = append(params, []byte{0x00, 0x00, 0x00, 0x02}...)

	params = append(params, fillBytes(14, amountIn.Bytes())...)
	params = append(params, pair.Bytes()...)
	params = append(params, tokenIn.Bytes()...)
	params = append(params, tokenOut.Bytes()...)

	params = append(params, fillBytes(1, buyConfigToBigInt(config).Bytes())...)

	if config.CalcAmountOut {
		params = append(params, fillBytes(2, fee.Bytes())...)
	} else {
		params = append(params, fillBytes(14, amountOut.Bytes())...)
	}

	params = append(params, fillBytes(14, minTokenOutBalance.Bytes())...)

	if config.FeeToBuilder {
		params = append(params, builderAddress.Bytes()...)
	}

	return params
}

func v3BuyFrontEncodeParams(
	amountIn *big.Int,
	pool common.Address,
	tokenIn common.Address,
	tokenOut common.Address,
	config *BuyConfig,
) []byte {
	params := make([]byte, 0)
	params = append(params, []byte{0x00, 0x00, 0x00, 0x04}...)

	params = append(params, fillBytes(14, amountIn.Bytes())...)
	params = append(params, pool.Bytes()...)
	params = append(params, tokenIn.Bytes()...)
	params = append(params, tokenOut.Bytes()...)

	params = append(params, fillBytes(1, buyConfigToBigInt(config).Bytes())...)

	return params
}

func v3BuyBackEncodeParams(
	amountIn *big.Int,
	pool common.Address,
	tokenIn common.Address,
	tokenOut common.Address,
	config *BuyConfig,
	minTokenOutBalance *big.Int,
	builderAddress common.Address,
) []byte {
	params := make([]byte, 0)
	params = append(params, []byte{0x00, 0x00, 0x00, 0x08}...)

	params = append(params, fillBytes(14, amountIn.Bytes())...)
	params = append(params, pool.Bytes()...)
	params = append(params, tokenIn.Bytes()...)
	params = append(params, tokenOut.Bytes()...)

	params = append(params, fillBytes(1, buyConfigToBigInt(config).Bytes())...)

	params = append(params, fillBytes(14, minTokenOutBalance.Bytes())...)

	if config.FeeToBuilder {
		params = append(params, builderAddress.Bytes()...)
	}
	return params
}

func fillBytes(l int, rawData []byte) []byte {
	rawLen := len(rawData)
	head := l - rawLen
	res := make([]byte, l)
	for i := 0; i < rawLen; i++ {
		res[head+i] = rawData[i]
	}
	return res
}

func mevCall(reqId string, state *state.StateDB, header *types.Header, s *BundleAPI, ctx context.Context, args *TransactionArgs, msg *core.Message, overrides *StateOverride, blockOverrides *BlockOverrides) (*core.ExecutionResult, error) {

	defer func(start time.Time) {
		log.Info("call_ExecutingEVMCallFinished", "runtime", time.Since(start), "reqId", reqId)
	}(time.Now())
	//result, err := doMevCall(ctx, s.b, args, state, header, overrides, blockOverrides, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
	result, err := doMevCall(ctx, s.b, args, msg, state, header, overrides, blockOverrides, 50*time.Millisecond, s.b.RPCGasCap())

	if err != nil {
		return nil, err
	}
	// If the result contains a revert reason, try to unpack and return it.
	if len(result.Revert()) > 0 {
		return nil, newRevertError(result.Revert())
	}
	return result, result.Err
}

func doMevCall(ctx context.Context, b Backend, args *TransactionArgs, msg *core.Message, state *state.StateDB, header *types.Header, overrides *StateOverride, blockOverrides *BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	if err := overrides.Apply(state); err != nil {
		return nil, err
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

	// Get a new instance of the EVM.
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	if blockOverrides != nil {
		blockOverrides.Apply(&blockCtx)
	}

	if msg == nil && args != nil {
		msgTmp, err2 := args.ToMessage(globalGasCap, blockCtx.BaseFee)
		if err2 != nil {
			return nil, err2
		}
		msg = msgTmp
	}

	evm := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	gopool.Submit(func() {
		<-ctx.Done()
		evm.Cancel()
	})

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := state.Error(); err != nil {
		return nil, err
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit)
	}
	return result, nil
}

func timeCost(reqId string, start time.Time) {
	tc := time.Since(start)
	log.Info("call_cost", "reqId", reqId, "ms", tc.Milliseconds())
}

func ApplyTransactionWithResultNew(config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config, receiptProcessors ...core.ReceiptProcessor) (*types.Receipt, *core.ExecutionResult, error) {
	msg, err := core.TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := core.NewEVMBlockContext(header, bc, author)
	txContext := core.NewEVMTxContext(msg)
	vmenv := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	defer func() {
		vmenv.Cancel()
	}()
	return applyTransactionWithResult(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv, receiptProcessors...)
}

func applyTransactionWithResult(msg *core.Message, config *params.ChainConfig, gp *core.GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM, receiptProcessors ...core.ReceiptProcessor) (*types.Receipt, *core.ExecutionResult, error) {
	// Create a new context to be used in the EVM environment.
	txContext := core.NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := core.ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	if tx.Type() == types.BlobTxType {
		receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * params.BlobTxBlobGasPerBlob)
		receipt.BlobGasPrice = evm.Context.BlobBaseFee
	}

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	for _, receiptProcessor := range receiptProcessors {
		receiptProcessor.Apply(receipt)
	}
	return receipt, result, err
}
