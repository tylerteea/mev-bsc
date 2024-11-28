package ethapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
	"time"

	"github.com/ethereum/go-ethereum/log"
)

const (
	V3       = int(1)
	Simulate = true

	frontAmountInString  = "frontAmountIn"
	frontAmountOutString = "frontAmountOut"

	backAmountInString  = "backAmountIn"
	backAmountOutString = "backAmountOut"

	front_amount_in_1  = "frontAmountIn1"
	front_amount_out_1 = "frontAmountOut1"
	front_amount_in_2  = "frontAmountIn2"
	front_amount_out_2 = "frontAmountOut2"
	front_diff         = "frontDiff"

	back_amount_in_1  = "backAmountIn1"
	back_amount_out_1 = "backAmountOut1"
	back_amount_in_2  = "backAmountIn2"
	back_amount_out_2 = "backAmountOut2"
	back_diff         = "backDiff"

	profitString = "profit"
	errorString  = "error"
	reasonString = "reason"
	defaultError = "default"
)

var pow1018 = math.Pow10(18)
var power18 = big.NewFloat(pow1018)

var ZeroHexBig = new(hexutil.Big)
var BigIntZeroValue = big.NewInt(0)
var BigIntOne = big.NewInt(1)
var BigIntTwo = big.NewInt(2)
var GweiOne = big.NewInt(1_000_000_000)
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

func FillBytes(l int, rawData []byte) []byte {
	rawLen := len(rawData)
	head := l - rawLen
	if head == 0 {
		return rawData
	}
	res := make([]byte, l)
	for i := 0; i < rawLen; i++ {
		res[head+i] = rawData[i]
	}
	return res
}

func mevCall(reqId string, state *state.StateDB, header *types.Header, s *BundleAPI, ctx context.Context, args *TransactionArgs, msg *core.Message, overrides *StateOverride, blockOverrides *BlockOverrides) (*core.ExecutionResult, error) {

	//defer func(start time.Time) {
	//log.Info("call_ExecutingEVMCallFinished", "runtime", time.Since(start), "reqId", reqId)
	//}(time.Now())
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

func ApplyTransactionWithResult(config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config, receiptProcessors ...core.ReceiptProcessor) (*types.Receipt, *core.ExecutionResult, error) {
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

func getERC20TokenBalance(ctx context.Context, s *BundleAPI, token common.Address, account common.Address, state *state.StateDB, header *types.Header) (*big.Int, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Info("recover...getERC20TokenBalance")
		}
	}()

	reqId := "getERC20TokenBalance_" + token.String() + "_" + account.String()

	newMethod := abi.NewMethod("balanceOf", "balanceOf", abi.Function, "pure", false, false, inp, oup)
	pack, err := newMethod.Inputs.Pack(account)
	var data = append(newMethod.ID, pack...)
	bytes := (hexutil.Bytes)(data)

	callArgs := &TransactionArgs{
		To:   &token,
		Data: &bytes,
	}
	callResult, err := mevCall(reqId, state, header, s, ctx, callArgs, nil, nil, nil)

	if callResult != nil {

		//log.Info("call_execute4", "reqId", reqId, "result", string(callResult.ReturnData))
		if len(callResult.Revert()) > 0 {

			revertReason := newRevertError(callResult.Revert())
			log.Info("call_result_not_nil_44",
				"reqId", reqId,
				"data", callResult,
				"revert", common.Bytes2Hex(callResult.Revert()),
				"revertReason", revertReason,
				"returnData", common.Bytes2Hex(callResult.Return()),
			)
			log.Info("call_execute5", "reqId", reqId, "revertReason", revertReason.reason)
			return nil, revertReason
		}

		if callResult.Err != nil {
			log.Info("call_execute7", "reqId", reqId, "err", callResult.Err)
			return nil, callResult.Err
		}
	}
	if err != nil {
		log.Info("call_execute6", "reqId", reqId, "err", err)
		return nil, err
	}

	balance := new(big.Int).SetBytes(callResult.Return())
	log.Info("call_balance_finish", "reqId", reqId, "balance", balance.String())

	return balance, nil
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

	inAddressType, _ := abi.NewType("address[]", "address[]", nil)
	inpa := []abi.Argument{
		{
			Name: "tokens",
			Type: inAddressType,
		},
	}

	outBalanceType, _ := abi.NewType("uint256[]", "uint256[]", nil)
	oupa := []abi.Argument{
		{
			Name: "memory",
			Type: outBalanceType,
		},
	}
	newMethod := abi.NewMethod("balancesOf", "balancesOf", abi.Function, "pure", false, false, inpa, oupa)
	pack, err := newMethod.Inputs.Pack(tokens)
	var data = append(newMethod.ID, pack...)
	bytes := (hexutil.Bytes)(data)

	callArgs := &TransactionArgs{
		To:   &contractAddress,
		Data: &bytes,
	}

	//log.Info("call_getTokenBalance_start", "reqId", reqId, "data", common.Bytes2Hex(bytes))

	callResult, err := mevCall(reqId, state, header, s, ctx, callArgs, nil, nil, nil)

	//log.Info("call_getTokenBalance1", "reqId", reqId)

	if callResult != nil {

		//log.Info("call_getTokenBalance2", "reqId", reqId, "result", string(callResult.ReturnData))
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
		//log.Info("call_getTokenBalance_ok", "reqId", reqId, "err", err)
		return balances, nil
	} else {
		log.Info("call_getTokenBalance_err", "reqId", reqId, "err", err)
		return nil, errors.New("转换失败")
	}
}
