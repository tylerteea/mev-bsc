package ethapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"
)

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
}

// CallBundle will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *BundleAPI) CallBundle(ctx context.Context, args CallBundleArgs) (map[string]interface{}, error) {
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
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)
	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}
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
		ParentHash: parent.Hash(),
		Number:     blockNumber,
		GasLimit:   gasLimit,
		Time:       timestamp,
		Difficulty: difficulty,
		Coinbase:   coinbase,
		BaseFee:    baseFee,
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		_, cancel = context.WithTimeout(ctx, timeout)
	} else {
		_, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	vmconfig := vm.Config{NoBaseFee: true}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	results := []map[string]interface{}{}
	coinbaseBalanceBefore := state.GetBalance(coinbase)

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

		coinbaseBalanceBeforeTx := state.GetBalance(coinbase)

		from, err := types.Sender(signer, tx)
		state.Prepare(rules, from, coinbase, tx.To(), vm.ActivePrecompiles(rules), tx.AccessList())

		receipt, result, err := core.ApplyTransactionWithResult(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
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
			jsonResult["error"] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				jsonResult["revert"] = string(revert)
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
		coinbaseDiffTx := new(big.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBeforeTx)
		jsonResult["coinbaseDiff"] = coinbaseDiffTx.String()
		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiffTx, gasFeesTx).String()
		jsonResult["gasPrice"] = new(big.Int).Div(coinbaseDiffTx, big.NewInt(int64(receipt.GasUsed))).String() // tx.GasPrice().String()
		jsonResult["gasUsed"] = receipt.GasUsed
		results = append(results, jsonResult)
	}

	ret := map[string]interface{}{}
	ret["results"] = results
	coinbaseDiff := new(big.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBefore)
	ret["coinbaseDiff"] = coinbaseDiff.String()
	ret["gasFees"] = gasFees.String()
	ret["ethSentToCoinbase"] = new(big.Int).Sub(coinbaseDiff, gasFees).String()
	ret["bundleGasPrice"] = new(big.Int).Div(coinbaseDiff, big.NewInt(int64(totalGasUsed))).String() // new(big.Int).Div(gasFees, big.NewInt(int64(totalGasUsed))).String()
	ret["totalGasUsed"] = totalGasUsed
	ret["stateBlockNumber"] = parent.Number.Int64()

	ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))
	return ret, nil
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

	// Get a new instance of the EVM.
	msg, err := args.ToMessage(globalGasCap, header.BaseFee)
	if err != nil {
		return map[string]interface{}{
			"error": err,
		}
	}

	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)

	evm, vmError := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)

	//evm, vmError, err := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true})
	if err != nil {
		return map[string]interface{}{
			"error": err,
		}
	}
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	gopool.Submit(func() {
		<-ctx.Done()
		evm.Cancel()
	})

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
		return map[string]interface{}{
			"error": err,
		}
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return map[string]interface{}{
			"error": fmt.Errorf("execution aborted (timeout = %v)", timeout),
		}
	}
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit),
		}
	}
	if len(result.Revert()) > 0 {
		revertErr := newRevertError(result)
		data, _ := json.Marshal(&revertErr)
		var result map[string]interface{}
		json.Unmarshal(data, &result)
		return result
	}
	if result.Err != nil {
		return map[string]interface{}{
			"error": "execution reverted",
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

// SbpArgs SandwichBestProfitArgs represents the arguments for a call.
type SbpArgs struct {
	Contract     common.Address `json:"contract"`
	Pair         common.Address `json:"pair"`
	TokenIn      common.Address `json:"tokenIn"`
	TokenOut     common.Address `json:"tokenOut"`
	BloxAddress  common.Address `json:"blox"`
	Balance      *big.Int       `json:"balance"`
	AmountIn     *big.Int       `json:"amountIn"`
	AmountOutMin *big.Int       `json:"amountOutMin"`
	BloxAmount   *big.Int       `json:"bloxAmount"`
	Fee          int64          `json:"fee"`
	Wallet       common.Address `json:"wallet"`
	VictimTxHash common.Hash    `json:"vTxHash"`
	DebugMode    bool           `json:"debugMode"`
	ZeroForOne   bool           `json:"zeroForOne"`
	Steps        *big.Int       `json:"steps"`
}

// SandwichBestProfit profit calculate
func (s *BundleAPI) SandwichBestProfit(ctx context.Context, sbp SbpArgs) (results []map[string]interface{}) {

	reqId := time.Now().UnixMilli()
	req, _ := json.Marshal(sbp)
	log.Info("call_SandwichBestProfit_1_", "reqId", reqId, "sbp", string(req))

	timeout := s.b.RPCEVMTimeout()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	defer cancel()
	defer func(results *[]map[string]interface{}) {
		if r := recover(); r != nil {
			oldResultJson, _ := json.Marshal(results)
			log.Info("call_SandwichBestProfit_old_result_", "reqId", reqId, "result", string(oldResultJson))
			results = new([]map[string]interface{})
			result := make(map[string]interface{})
			result["error"] = "panic"
			result["reason"] = r
			*results = append(*results, result)
			newResultJson, _ := json.Marshal(results)
			log.Info("call_SandwichBestProfit_defer_result_", "reqId", reqId, "result", string(newResultJson))
		}
	}(&results)

	if sbp.Balance.Int64() == 0 {
		result := make(map[string]interface{})
		result["error"] = "args_err"
		result["reason"] = "balance_is_0"
		results = append(results, result)
		return results
	}
	balance := sbp.Balance

	amountIn := sbp.AmountIn
	wallet := sbp.Wallet
	victimTxHash := sbp.VictimTxHash
	amountOutMin := sbp.AmountOutMin

	// 根据受害人tx hash  从内存池得到tx msg
	victimTransaction := s.b.GetPoolTransaction(victimTxHash)

	//初始化数据
	head := s.chain.CurrentHeader()
	blockNo := head.Number.Uint64()

	// 如果是测试阶段，可以使用已经上块的tx
	if sbp.DebugMode {
		if victimTransaction == nil {
			tx, _, blockNumber, _, _ := s.b.GetTransaction(ctx, victimTxHash)
			if tx != nil {
				blockNo = blockNumber - 1
				head = s.chain.GetHeaderByNumber(blockNo)
				victimTransaction = tx
			}
		}
	}
	// 获取不到 直接返回
	if victimTransaction == nil {
		result := make(map[string]interface{})
		result["error"] = "tx_is_nil"
		result["reason"] = "GetPoolTransaction and GetTransaction all nil : " + victimTxHash.Hex()
		results = append(results, result)
		resultJson, _ := json.Marshal(result)
		log.Info("call_SandwichBestProfit_2_", "reqId", reqId, "result", string(resultJson))
		return results
	}
	number := rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(blockNo))

	stateDB, _, _ := s.b.StateAndHeaderByNumberOrHash(ctx, number)
	nonce := stateDB.GetNonce(wallet)
	globalGasCap := s.b.RPCGasCap()

	log.Info("call_SandwichBestProfit_3_", "reqId", reqId, "blockNo", blockNo, "nonce", nonce, "globalGasCap", globalGasCap)

	victimTxMsg, victimTxMsgErr := core.TransactionToMessage(victimTransaction, types.MakeSigner(s.b.ChainConfig(), head.Number, head.Time), head.BaseFee)

	if victimTxMsgErr != nil {
		result := make(map[string]interface{})
		result["error"] = "victimTxMsgErr"
		result["reason"] = victimTxMsgErr
		results = append(results, result)

		resultJson, _ := json.Marshal(result)
		log.Info("call_SandwichBestProfit_4_", "reqId", reqId, "result", string(resultJson))
		return results
	}
	victimTxContext := core.NewEVMTxContext(victimTxMsg)

	//计算出每次步长
	stepAmount := new(big.Int).Quo(new(big.Int).SetInt64(0).Sub(balance, amountIn), sbp.Steps)

	//初始化整个执行ladder结构
	var ladder []*big.Int
	for amountIn.Cmp(balance) < 0 {
		ladder = append(ladder, new(big.Int).Set(amountIn))
		//累加
		amountIn = new(big.Int).Add(amountIn, stepAmount)
	}

	var wg = new(sync.WaitGroup)
	wg.Add(len(ladder))

	//并发执行模拟调用，记录结果
	for _, amountInReal := range ladder {
		sdb := stateDB.Copy()
		worker(ctx, results, head, victimTxMsg, victimTxContext, wg, sbp, s, reqId, amountOutMin, sdb, amountInReal, globalGasCap)
	}
	wg.Wait()
	resultJson, _ := json.Marshal(results)
	log.Info("call_SandwichBestProfit_5_", "reqId", reqId, "result", string(resultJson))
	return results
}

// SandwichBestProfit3Search profit calculate
func (s *BundleAPI) SandwichBestProfit3Search(ctx context.Context, sbp SbpArgs) (results []map[string]interface{}) {

	reqId := time.Now().UnixMilli()
	req, _ := json.Marshal(sbp)
	log.Info("call_sbp_1_", "reqId", reqId, "sbp", string(req))

	timeout := s.b.RPCEVMTimeout()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	defer cancel()
	defer func(results *[]map[string]interface{}) {
		if r := recover(); r != nil {
			oldResultJson, _ := json.Marshal(results)
			log.Info("call_sbp_old_result_", "reqId", reqId, "result", string(oldResultJson))
			results = new([]map[string]interface{})
			result := make(map[string]interface{})
			result["error"] = "panic"
			result["reason"] = r
			*results = append(*results, result)
			newResultJson, _ := json.Marshal(results)
			log.Info("call_sbp_defer_result_", "reqId", reqId, "result", string(newResultJson))
		}
	}(&results)

	if sbp.Balance.Int64() == 0 {
		result := make(map[string]interface{})
		result["error"] = "args_err"
		result["reason"] = "balance_is_0"
		results = append(results, result)
		return results
	}

	victimTxHash := sbp.VictimTxHash
	// 根据受害人tx hash  从内存池得到tx msg
	victimTransaction := s.b.GetPoolTransaction(victimTxHash)

	//初始化数据
	head := s.chain.CurrentHeader()
	blockNo := head.Number.Uint64()

	// 如果是测试阶段，可以使用已经上块的tx
	if sbp.DebugMode {
		if victimTransaction == nil {
			tx, _, blockNumber, _, _ := s.b.GetTransaction(ctx, victimTxHash)
			if tx != nil {
				blockNo = blockNumber - 1
				head = s.chain.GetHeaderByNumber(blockNo)
				victimTransaction = tx
			}
		}
	}
	// 获取不到 直接返回
	if victimTransaction == nil {
		result := make(map[string]interface{})
		result["error"] = "tx_is_nil"
		result["reason"] = "GetPoolTransaction and GetTransaction all nil : " + victimTxHash.Hex()
		results = append(results, result)
		resultJson, _ := json.Marshal(result)
		log.Info("call_sbp_2_", "reqId", reqId, "result", string(resultJson))
		return results
	}
	number := rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(blockNo))

	stateDB, _, _ := s.b.StateAndHeaderByNumberOrHash(ctx, number)
	globalGasCap := s.b.RPCGasCap()

	log.Info("call_sbp_3_", "reqId", reqId, "blockNo", blockNo, "globalGasCap", globalGasCap)

	victimTxMsg, victimTxMsgErr := core.TransactionToMessage(victimTransaction, types.MakeSigner(s.b.ChainConfig(), head.Number, head.Time), head.BaseFee)

	if victimTxMsgErr != nil {
		result := make(map[string]interface{})
		result["error"] = "victimTxMsgErr"
		result["reason"] = victimTxMsgErr
		results = append(results, result)

		resultJson, _ := json.Marshal(result)
		log.Info("call_sbp_4_", "reqId", reqId, "result", string(resultJson))
		return results
	}
	victimTxContext := core.NewEVMTxContext(victimTxMsg)

	//计算出每次步长
	stepAmount := new(big.Int).Quo(new(big.Int).SetInt64(0).Sub(sbp.Balance, sbp.AmountIn), sbp.Steps)

	args := &CallArgs{
		ctx:             ctx,
		head:            head,
		s:               s,
		blockNo:         hexutil.Uint64(blockNo),
		sdb:             stateDB,
		victimTxContext: victimTxContext,
		victimTxMsg:     victimTxMsg,
		timeout:         timeout,
		globalGasCap:    globalGasCap,
		sbp:             sbp,
	}
	totalCount, maxProfitX, maxProfitY, getMaxErr := getMax(args, sbp.AmountIn, sbp.Balance, stepAmount, sbp.Steps)

	log.Info("call_sbp_getMax_", "reqId", reqId, "totalCount", totalCount, "maxProfitX", maxProfitX, "maxProfitY", maxProfitY, "err", getMaxErr)
	if getMaxErr != nil {
		result := make(map[string]interface{})
		result["error"] = "getMaxErr"
		result["reason"] = getMaxErr
		results = append(results, result)
		return results
	}

	result := make(map[string]interface{})
	result["tokenIn"] = sbp.TokenIn
	result["tokenOut"] = sbp.TokenOut
	result["amountIn"] = maxProfitX
	result["amountOut"] = maxProfitY
	results = append(results, result)
	resultJson, _ := json.Marshal(result)
	log.Info("call_sbp_end_", "reqId", reqId, "result", string(resultJson))

	return results
}

func realCall(
	ctx context.Context,
	head *types.Header,
	s *BundleAPI,
	sbp SbpArgs,
	reqId int64,
	amountOutMin *big.Int,
	stateDb *state.StateDB,
	victimTxMsg *core.Message,
	victimTxContext vm.TxContext,
	amountIn *big.Int,
	globalGasCap uint64) (map[string]interface{}, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Info("call_SandwichBestProfit_defer_err_", "reqId", reqId, "err", r)
		}
	}()

	evmContext := core.NewEVMBlockContext(head, s.chain, nil)

	result := make(map[string]interface{})

	gasPool := new(core.GasPool).AddGas(math.MaxUint64)

	sdb := stateDb.Copy()

	// 抢跑----------------------------------------------------------------------------------------
	frontAmountOut, fErr := execute(ctx, sbp, reqId, amountOutMin, sbp.ZeroForOne, sbp.TokenIn, sbp.TokenOut, amountIn, evmContext, sdb, s, gasPool, globalGasCap, head)

	if fErr != nil {
		result["error"] = "frontCallErr"
		result["reason"] = fErr
		return result, fErr
	}

	// 受害者----------------------------------------------------------------------------------------
	vmEnv := vm.NewEVM(evmContext, victimTxContext, sdb, s.chain.Config(), vm.Config{NoBaseFee: true})
	victimTxCallResult, victimTxCallErr := core.ApplyMessage(vmEnv, victimTxMsg, gasPool)

	if victimTxCallErr != nil {
		result["error"] = "victimTxCallErr"
		result["reason"] = victimTxCallErr
		return result, victimTxCallErr
	}
	// todo  假设 amount in  = x 的时候  Revert 了， 那么大于 x 都停了, 目前做不到，后续增加二分搜索实现
	if len(victimTxCallResult.Revert()) > 0 {
		revertErr := newRevertError(victimTxCallResult)
		data, _ := json.Marshal(&revertErr)
		_ = json.Unmarshal(data, &result)
		result["error"] = "execution_reverted"
		return result, revertErr
	}
	if victimTxCallResult.Err != nil {
		result["error"] = "execution_victimTxCallResultErr"
		result["reason"] = victimTxCallResult.Err
		return result, victimTxCallResult.Err
	}

	// 跟跑----------------------------------------------------------------------------------------
	backAmountOut, bErr := execute(ctx, sbp, reqId, amountOutMin, sbp.ZeroForOne, sbp.TokenOut, sbp.TokenIn, frontAmountOut, evmContext, sdb, s, gasPool, globalGasCap, head)

	if bErr != nil {
		result["error"] = "backCallErr"
		result["reason"] = bErr
		return result, bErr
	}
	result["amountIn"] = new(big.Int).Set(amountIn)
	result["amountOut"] = new(big.Int).Set(backAmountOut)
	return result, nil
}

type CallArgs struct {
	ctx             context.Context
	head            *types.Header
	s               *BundleAPI
	blockNo         hexutil.Uint64
	sdb             *state.StateDB
	victimTxContext vm.TxContext
	victimTxMsg     *core.Message
	timeout         time.Duration
	globalGasCap    uint64
	sbp             SbpArgs
	reqId           int64
}

func worker(
	ctx context.Context,
	results []map[string]interface{},
	head *types.Header,
	victimTxMsg *core.Message,
	victimTxContext vm.TxContext,
	wg *sync.WaitGroup,
	sbp SbpArgs,
	s *BundleAPI,
	reqId int64,
	amountOutMin *big.Int,
	statedb *state.StateDB,
	amountIn *big.Int,
	globalGasCap uint64) {

	defer func() {
		if r := recover(); r != nil {
			log.Info("call_SandwichBestProfit_defer_err_", "reqId", reqId, "err", r)
			wg.Done()
		}
	}()

	evmContext := core.NewEVMBlockContext(head, s.chain, nil)

	result := make(map[string]interface{})

	gasPool := new(core.GasPool).AddGas(math.MaxUint64)

	// 抢跑----------------------------------------------------------------------------------------
	frontAmountOut, fErr := execute(ctx, sbp, reqId, amountOutMin, sbp.ZeroForOne, sbp.TokenIn, sbp.TokenOut, amountIn, evmContext, statedb, s, gasPool, globalGasCap, head)

	if fErr != nil {
		result["error"] = "frontCallErr"
		result["reason"] = fErr.Error()
		result["amountIn"] = amountIn.String()
		results = append(results, result)
		wg.Done()
		return
	}
	// 受害者----------------------------------------------------------------------------------------
	vmEnv := vm.NewEVM(evmContext, victimTxContext, statedb, s.chain.Config(), vm.Config{NoBaseFee: true})
	err := gopool.Submit(func() {
		vmEnv.Cancel()
	})
	if err != nil {
		wg.Done()
		return
	}
	victimTxCallResult, victimTxCallErr := core.ApplyMessage(vmEnv, victimTxMsg, gasPool)

	log.Info("call_victimTx", "reqId", reqId, "victimTxCallResult", victimTxCallResult)

	if victimTxCallErr != nil {
		result["error"] = "victimTxCallErr"
		result["reason"] = victimTxCallErr.Error()
		result["amountIn"] = amountIn.String()
		results = append(results, result)
		wg.Done()
		return
	}
	if len(victimTxCallResult.Revert()) > 0 {
		revertErr := newRevertError(victimTxCallResult)
		data, _ := json.Marshal(&revertErr)
		_ = json.Unmarshal(data, &result)
		result["error"] = "execution_victimTx_reverted"
		result["reason"] = victimTxCallResult.Err.Error()
		result["amountIn"] = amountIn.String()
		results = append(results, result)
		wg.Done()
		return
	}
	if victimTxCallResult.Err != nil {
		result["error"] = "execution_victimTx_callResult_err"
		result["reason"] = victimTxCallResult.Err.Error()
		result["amountIn"] = amountIn.String()
		results = append(results, result)
		wg.Done()
		return
	}

	data := victimTxCallResult.Return()
	bytes2Hex := common.Bytes2Hex(data)
	dst := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(dst, data)

	log.Info("call_victimTx", "reqId", reqId, "bytes2Hex", bytes2Hex, "string", string(dst))

	// 跟跑----------------------------------------------------------------------------------------
	backAmountOut, bErr := execute(ctx, sbp, reqId, amountOutMin, !sbp.ZeroForOne, sbp.TokenOut, sbp.TokenIn, frontAmountOut, evmContext, statedb, s, gasPool, globalGasCap, head)

	if bErr != nil {
		result["error"] = "backCallErr"
		result["reason"] = bErr.Error()
		result["amountIn"] = amountIn.String()
		results = append(results, result)
		wg.Done()
		return
	}

	result["tokenIn"] = sbp.TokenIn
	result["tokenOut"] = sbp.TokenOut
	result["amountIn"] = new(big.Int).Set(amountIn)
	result["amountOut"] = new(big.Int).Set(backAmountOut)
	results = append(results, result)
	wg.Done()
}
func execute(ctx context.Context,
	sbp SbpArgs,
	reqId int64,
	amountOunMin *big.Int,
	zeroForOne bool,
	tokenIn common.Address,
	tokenOut common.Address,
	amountIn *big.Int,
	evmContext vm.BlockContext,
	sdb *state.StateDB,
	s *BundleAPI,
	gasPool *core.GasPool,
	globalGasCap uint64,
	head *types.Header) (*big.Int, error) {

	log.Info("call_newData_args",
		"reqId", reqId,
		"amountOunMin", amountOunMin,
		"bloxAmount", sbp.BloxAmount,
		"bloxAddress", sbp.BloxAddress,
		"pair", sbp.Pair,
		"tokenIn", tokenIn,
		"fee", sbp.Fee,
		"amountIn", amountIn,
		"zeroForOne", zeroForOne,
	)
	data := newData(amountOunMin, sbp.BloxAmount, sbp.BloxAddress, sbp.Pair, tokenIn, tokenOut, big.NewInt(sbp.Fee), amountIn, zeroForOne)

	log.Info("call_newData_result", "reqId", reqId, "data_hex", common.Bytes2Hex(data))

	bytes := hexutil.Bytes(data)
	callArgs := TransactionArgs{
		From: &sbp.Wallet,
		To:   &sbp.Contract,
		Data: &bytes,
	}
	callResult, err := mevCall(sdb, head, s, ctx, callArgs, nil, nil)

	log.Info("call_result",
		"reqId", reqId,
		"amountIn", amountIn,
		"zeroForOne", zeroForOne,
		"data", callResult,
		"revert", common.Bytes2Hex(callResult.Revert()),
		"returnData", common.Bytes2Hex(callResult.Return()),
	)

	if err != nil {
		log.Info("call_applyMessage_err", "reqId", reqId, "error", err)
		return nil, err
	}
	if callResult.Err != nil {
		log.Info("call_applyMessage_callResult_err", "reqId", reqId, "error", callResult.Err)
		return nil, callResult.Err
	}
	amountOut := new(big.Int).SetBytes(callResult.Return())

	log.Info("call_success", "reqId", reqId, "amountIn", amountIn, "zeroForOne", zeroForOne, "amountOut", amountOut)
	return amountOut, nil
}

func newData(
	amountOutMin *big.Int,
	bloxAmount *big.Int,
	bloxAddress common.Address,
	pairAddress common.Address,
	tokenIn common.Address,
	tokenOut common.Address,
	fee *big.Int,
	amountIn *big.Int,
	zeroForOne bool,
) []byte {

	params := make([]byte, 0)
	params = append(params, []byte{0xa9, 0x24, 0x83, 0xf0}...)
	params = append(params, fillBytes(14, amountIn.Bytes())...)
	params = append(params, pairAddress.Bytes()...)
	params = append(params, tokenIn.Bytes()...)
	params = append(params, tokenOut.Bytes()...)
	params = append(params, bloxAddress.Bytes()...)
	params = append(params, fillBytes(14, amountOutMin.Bytes())...)
	params = append(params, fillBytes(2, fee.Bytes())...)
	if zeroForOne {
		params = append(params, []byte{1}...)
	} else {
		params = append(params, []byte{0}...)
	}
	params = append(params, fillBytes(14, bloxAmount.Bytes())...)

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

func mevCall(state *state.StateDB, header *types.Header, s *BundleAPI, ctx context.Context, args TransactionArgs, overrides *StateOverride, blockOverrides *BlockOverrides) (*core.ExecutionResult, error) {

	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	return doMevCall(ctx, s.b, args, state, header, overrides, blockOverrides, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
}

func doMevCall(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, overrides *StateOverride, blockOverrides *BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {

	if err := overrides.Apply(state); err != nil {
		return nil, err
	}
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
	msg, err := args.ToMessage(globalGasCap, header.BaseFee)
	if err != nil {
		return nil, err
	}
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	if blockOverrides != nil {
		blockOverrides.Apply(&blockCtx)
	}
	evm, vmError := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)

	gopool.Submit(func() {
		<-ctx.Done()
		evm.Cancel()
	})

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
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
