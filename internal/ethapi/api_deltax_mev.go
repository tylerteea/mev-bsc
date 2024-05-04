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
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/crypto/sha3"

	"gonum.org/v1/gonum/optimize"
)

const (
	V2 = int(2)
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
			jsonResult["error"] = result.Err.Error()
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

	//// todo
	//newResultJson, _ := json.Marshal(ret)
	//log.Info("call_bundle_result", "ret", string(newResultJson))

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

func (s *BundleAPI) GetNowValidators(ctx context.Context, number *rpc.BlockNumber) map[string]interface{} {

	log.Info("GetValidators_start", "number", number)

	result := make(map[string]interface{})

	result["number"] = number

	result["error"] = "default"
	result["reason"] = "default"

	log.Info("初始化parliaAPI", "number", number)

	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = s.chain.CurrentHeader()
	} else {
		header = s.chain.GetHeaderByNumber(uint64(number.Int64()))
	}

	if header == nil {
		result["error"] = "header_nil"
		result["reason"] = "header_nil"
		return result
	}

	validators, err := s.b.Engine().GetNowValidators(s.chain, header)

	if err == nil {
		result["error"] = ""
		result["reason"] = ""
		result["validators"] = validators
	} else {
		result["error"] = err
		result["reason"] = err
	}

	marshal, _ := json.Marshal(result)
	log.Info("打印validators", "number", number, "validators", string(marshal))

	return result
}

func (s *BundleAPI) GetBuilder(ctx context.Context, number *rpc.BlockNumber) map[string]interface{} {

	log.Info("GetBuilder_start", "number", number)

	result := make(map[string]interface{})

	result["number"] = number

	result["error"] = "default"
	result["reason"] = "default"

	validatorResult := s.GetNowValidators(ctx, number)

	if validatorResult == nil || validatorResult["error"] != "" {
		return validatorResult
	}

	validators, ok := validatorResult["validators"].([]common.Address)

	if !ok {
		result["error"] = "validator_err"
		result["reason"] = "validator_err"
		return validatorResult
	}

	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = s.chain.CurrentHeader()
	} else {
		header = s.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the validators from its snapshot
	if header == nil {
		result["error"] = "header_nil"
		result["reason"] = "header_nil"
		return result
	}

	lengthValidators := len(validators)
	offset := (header.Number.Uint64() + 1) % uint64(lengthValidators)

	builderMap := make(map[uint64]interface{})

	for i := offset; i < uint64(lengthValidators); i++ {
		builderMap[offset] = validators[offset]
	}

	result["error"] = ""
	result["reason"] = ""
	result["builderMap"] = builderMap

	marshal, _ := json.Marshal(result)
	log.Info("打印builder", "number", number, "builder", string(marshal))

	return result
}

// SbpBuyArgs SandwichBestProfitArgs represents the arguments for a call.
type SbpBuyArgs struct {
	Eoa             common.Address `json:"eoa"`
	Contract        common.Address `json:"contract"`
	Balance         *big.Int       `json:"balance"`
	Token2          common.Address `json:"token2"`
	Token3          common.Address `json:"token3"`
	PairOrPool2     common.Address `json:"pairOrPool2"`
	ZeroForOne2     bool           `json:"zeroForOne2"`
	Fee2            *big.Int       `json:"fee2"`
	Version2        int            `json:"version2"`
	AmountInMin     *big.Int       `json:"amountInMin"`
	AmountOutMin    *big.Int       `json:"amountOutMin"`
	BriberyAddress  common.Address `json:"briberyAddress"`
	VictimTxHash    common.Hash    `json:"vTxHash"`
	BuyOrSale       bool           `json:"buyOrSale"`
	Steps           *big.Int       `json:"steps"`
	ReqId           string         `json:"reqId"`
	FuncEvaluations int            `json:"funcEvaluations"`
	RunTimeout      int            `json:"runTimeout"`
	Iterations      int            `json:"iterations"`
	Concurrent      int            `json:"concurrent"`
	InitialValues   float64        `json:"initialValues"`
	SubOne          bool           `json:"subOne"`
	LogEnable       bool           `json:"logEnable"`
}

type SbpSaleArgs struct {
	Eoa      common.Address `json:"eoa"`
	Contract common.Address `json:"contract"`
	Balance  *big.Int       `json:"balance"`

	Token1      common.Address `json:"token1,omitempty"`
	Token2      common.Address `json:"token2"`
	Token3      common.Address `json:"token3"`
	PairOrPool1 common.Address `json:"pairOrPool1,omitempty"`
	ZeroForOne1 bool           `json:"zeroForOne1,omitempty"`
	Fee1        *big.Int       `json:"fee1,omitempty"`
	PairOrPool2 common.Address `json:"pairOrPool2"`
	ZeroForOne2 bool           `json:"zeroForOne2"`
	Fee2        *big.Int       `json:"fee2"`
	Version2    int            `json:"version2"`
	BuyOrSale   bool           `json:"buyOrSale"`
	SubOne      bool           `json:"subOne"`

	AmountInMin     *big.Int       `json:"amountInMin"`
	AmountOutMin    *big.Int       `json:"amountOutMin"`
	BriberyAddress  common.Address `json:"briberyAddress"`
	VictimTxHash    common.Hash    `json:"vTxHash"`
	Steps           *big.Int       `json:"steps"`
	ReqId           string         `json:"reqId"`
	FuncEvaluations int            `json:"funcEvaluations"`
	RunTimeout      int            `json:"runTimeout"`
	Iterations      int            `json:"iterations"`
	Concurrent      int            `json:"concurrent"`
	InitialValues   float64        `json:"initialValues"`
	LogEnable       bool           `json:"logEnable"`
}

type SbpBatchArgs struct {
	// 账户及合约参数
	Eoa            common.Address `json:"eoa"`
	Contract       common.Address `json:"contract"`
	Balance        *big.Int       `json:"balance"`
	AmountInMin    *big.Int       `json:"amountInMin"`
	AmountOutMin   *big.Int       `json:"amountOutMin"`
	BriberyAddress common.Address `json:"briberyAddress"`
	VictimTxHash   common.Hash    `json:"vTxHash"`

	// minimize参数
	Steps           *big.Int `json:"steps"`
	ReqId           string   `json:"reqId"`
	FuncEvaluations int      `json:"funcEvaluations"`
	RunTimeout      int      `json:"runTimeout"`
	Iterations      int      `json:"iterations"`
	Concurrent      int      `json:"concurrent"`
	InitialValues   float64  `json:"initialValues"`
	LogEnable       bool     `json:"logEnable"`

	// 三明治pair参数
	SbpPairs []*SbpPairArgs `json:"sbpPairArgs"`
}

// SbpPairArgs 三明治pair参数
type SbpPairArgs struct {
	PairIndex   int            `json:"pairIndex"`
	Token1      common.Address `json:"token1,omitempty"`
	Token2      common.Address `json:"token2"`
	Token3      common.Address `json:"token3"`
	PairOrPool1 common.Address `json:"pairOrPool1,omitempty"`
	ZeroForOne1 bool           `json:"zeroForOne1,omitempty"`
	Fee1        *big.Int       `json:"fee1,omitempty"`
	PairOrPool2 common.Address `json:"pairOrPool2"`
	ZeroForOne2 bool           `json:"zeroForOne2"`
	Fee2        *big.Int       `json:"fee2"`
	Version2    int            `json:"version2"`
	BuyOrSale   bool           `json:"buyOrSale"`
	SubOne      bool           `json:"subOne"`
}

// SandwichBestProfitBatch profit calculate
func (s *BundleAPI) SandwichBestProfitBatch(ctx context.Context, sbp SbpBatchArgs) map[string]interface{} {

	result := make(map[string]interface{})

	result["error"] = "default"
	result["reason"] = "default"

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
				log.Info("call_sbp_old_result_", "reqId", sbp.ReqId, "result", string(oldResultJson))
			}
			result["error"] = "panic"
			result["reason"] = r
			if sbp.LogEnable {
				newResultJson, _ := json.Marshal(result)
				log.Info("call_sbp_defer_result_", "reqId", sbp.ReqId, "result", string(newResultJson))
			}
		}
	}(&result)

	sbpPairs := sbp.SbpPairs

	if sbpPairs == nil {
		result["error"] = "args_SbpPair"
		result["reason"] = "args_SbpPair"
		return result
	}

	wg := new(sync.WaitGroup)
	wg.Add(len(sbpPairs))

	channelResult := make(chan map[string]interface{})

	go func() {
		defer close(channelResult) // 等待wg 执行完后关闭channel
		wg.Wait()
	}()

	for _, sbpPair := range sbpPairs {
		go bestProfit(ctx, channelResult, wg, sbp, sbpPair, s)
	}

	maxProfit := big.NewInt(0)

	for singleResult := range channelResult {

		if singleResult["error"] == nil && singleResult["profit"] != nil {
			profit, ok := singleResult["profit"].(*big.Int)

			if ok && profit.Cmp(big.NewInt(0)) > 0 {
				if profit.Cmp(maxProfit) > 0 {
					maxProfit = profit
					result = singleResult
				}
			}
		}
	}
	if maxProfit.Cmp(big.NewInt(0)) <= 0 {
		result["error"] = "profit_too_low"
		result["reason"] = "profit_too_low"
	}

	if sbp.LogEnable {
		resultJson, _ := json.Marshal(result)
		log.Info("call_sbp_batch_end", "reqId", sbp.ReqId, "result", string(resultJson))
	}

	return result
}

func bestProfit(ctx context.Context, channelResult chan map[string]interface{}, wg *sync.WaitGroup, sbp SbpBatchArgs, sbpPair *SbpPairArgs, s *BundleAPI) {

	result := make(map[string]interface{})

	defer func() {
		if r := recover(); r != nil {
			channelResult <- result
			wg.Done()
		} else {
			channelResult <- result
			wg.Done()
		}
	}()

	reqId := sbp.ReqId

	if sbpPair.BuyOrSale {
		reqId = reqId + "_buy_" + sbpPair.PairOrPool2.String()
	} else {
		reqId = reqId + "_sale_" + sbpPair.PairOrPool1.String()
	}

	sbpSaleArgs := SbpSaleArgs{

		// 账户及合约公共参数
		Eoa:            sbp.Eoa,
		Contract:       sbp.Contract,
		Balance:        sbp.Balance,
		AmountInMin:    sbp.AmountInMin,
		AmountOutMin:   sbp.AmountOutMin,
		BriberyAddress: sbp.BriberyAddress,
		VictimTxHash:   sbp.VictimTxHash,

		// minimize公共参数
		Steps:           sbp.Steps,
		ReqId:           reqId, // 使用新生成的id
		FuncEvaluations: sbp.FuncEvaluations,
		RunTimeout:      sbp.RunTimeout,
		Iterations:      sbp.Iterations,
		Concurrent:      sbp.Concurrent,
		InitialValues:   sbp.InitialValues,
		LogEnable:       sbp.LogEnable,

		// 三明治pair参数
		Token1:      sbpPair.Token1,
		Token2:      sbpPair.Token2,
		Token3:      sbpPair.Token3,
		PairOrPool1: sbpPair.PairOrPool1,
		ZeroForOne1: sbpPair.ZeroForOne1,
		Fee1:        sbpPair.Fee1,
		PairOrPool2: sbpPair.PairOrPool2,
		ZeroForOne2: sbpPair.ZeroForOne2,
		Fee2:        sbpPair.Fee2,
		Version2:    sbpPair.Version2,
		SubOne:      sbpPair.SubOne,
		BuyOrSale:   sbpPair.BuyOrSale,
	}
	result = s.SandwichBestProfitMinimizeSale(ctx, sbpSaleArgs)
	result["pairIndex"] = sbpPair.PairIndex
}

// SandwichBestProfitMinimizeBuy profit calculate
func (s *BundleAPI) SandwichBestProfitMinimizeBuy(ctx context.Context, sbp SbpBuyArgs) map[string]interface{} {

	sbpSaleArgs := SbpSaleArgs{
		Eoa:             sbp.Eoa,
		Contract:        sbp.Contract,
		Balance:         sbp.Balance,
		Token1:          common.Address{},
		Token2:          sbp.Token2,
		Token3:          sbp.Token3,
		PairOrPool1:     common.Address{},
		ZeroForOne1:     false,
		Fee1:            nil,
		PairOrPool2:     sbp.PairOrPool2,
		ZeroForOne2:     sbp.ZeroForOne2,
		Fee2:            sbp.Fee2,
		Version2:        sbp.Version2,
		AmountInMin:     sbp.AmountInMin,
		AmountOutMin:    sbp.AmountOutMin,
		BriberyAddress:  sbp.BriberyAddress,
		VictimTxHash:    sbp.VictimTxHash,
		BuyOrSale:       sbp.BuyOrSale,
		Steps:           sbp.Steps,
		ReqId:           sbp.ReqId,
		FuncEvaluations: sbp.FuncEvaluations,
		RunTimeout:      sbp.RunTimeout,
		Iterations:      sbp.Iterations,
		Concurrent:      sbp.Concurrent,
		InitialValues:   sbp.InitialValues,
		SubOne:          sbp.SubOne,
		LogEnable:       sbp.LogEnable,
	}

	return s.SandwichBestProfitMinimizeSale(ctx, sbpSaleArgs)
}

// SandwichBestProfitMinimizeSale profit calculate
func (s *BundleAPI) SandwichBestProfitMinimizeSale(ctx context.Context, sbp SbpSaleArgs) map[string]interface{} {

	result := make(map[string]interface{})

	result["error"] = "default"
	result["reason"] = "default"

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
			result["error"] = "panic"
			result["reason"] = r
			if sbp.LogEnable {
				newResultJson, _ := json.Marshal(result)
				log.Info("call_sbp_defer_result_", "reqId", reqId, "result", string(newResultJson))
			}
		}
	}(&result)

	if sbp.Balance.Cmp(big.NewInt(0)) == 0 {
		result["error"] = "args_err"
		result["reason"] = "balance_is_0"
		return result
	}
	balance := sbp.Balance

	minAmountIn := sbp.AmountInMin
	victimTxHash := sbp.VictimTxHash

	// 根据受害人tx hash  从内存池得到tx msg
	victimTransaction := s.b.GetPoolTransaction(victimTxHash)

	// 获取不到 直接返回
	if victimTransaction == nil {
		result["error"] = "tx_is_nil"
		result["reason"] = "GetPoolTransaction and GetTransaction all nil : " + victimTxHash.Hex()
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
		if workerResults["error"] == nil && workerResults["profit"] != nil {
			profit, ok := workerResults["profit"].(*big.Int)
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
		result["error"] = "minimize_err"
		result["reason"] = err.Error()
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
		result["error"] = "minimize_result_out_of_limit"
		result["reason"] = quoteAmountIn
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

	if workerResults["error"] == nil && workerResults["profit"] != nil {
		profit, ok := workerResults["profit"].(*big.Int)
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
			log.Info("call_SandwichBestProfit_defer_err_", "reqAndIndex", reqAndIndex, "err", r)
		}
	}()

	result := make(map[string]interface{})

	// 抢跑----------------------------------------------------------------------------------------
	startTime := time.Now()
	frontAmountOut, fErr := execute(ctx, reqAndIndex, true, sbp, amountIn, statedb, s, head)
	costTime := time.Since(startTime).Milliseconds()

	if sbp.LogEnable {
		log.Info("call_execute_front", "reqAndIndex", reqAndIndex, "amountIn", amountIn, "frontAmountOut", frontAmountOut, "fErr", fErr, "cost_time", costTime)
	}
	if fErr != nil {
		result["error"] = "frontCallErr"
		result["reason"] = fErr.Error()
		result["amountIn"] = amountIn.String()
		return result
	}

	if sbp.SubOne {
		frontAmountOut = new(big.Int).Sub(frontAmountOut, big.NewInt(1))
	}

	if frontAmountOut.Cmp(big.NewInt(0)) == 0 {
		result["error"] = "frontAmountOutZero"
		result["reason"] = "frontAmountOutZero"
		result["amountIn"] = amountIn.String()
		return result
	}

	// 受害者----------------------------------------------------------------------------------------
	victimStartTime := time.Now()
	victimTxMsg, victimTxMsgErr := core.TransactionToMessage(victimTransaction, types.MakeSigner(s.b.ChainConfig(), head.Number, head.Time), head.BaseFee)

	if victimTxMsgErr != nil {
		result["error"] = "victimTxMsgErr"
		result["reason"] = victimTxMsgErr
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
		result["error"] = "victimPoolSubmit"
		result["reason"] = err.Error()
		return result
	}
	gasPool := new(core.GasPool).AddGas(math.MaxUint64)
	victimTxCallResult, victimTxCallErr := core.ApplyMessage(vmEnv, victimTxMsg, gasPool)

	victimCostTime := time.Since(victimStartTime).Milliseconds()

	if sbp.LogEnable {
		log.Info("call_execute_victim", "reqAndIndex", reqAndIndex, "cost_time", victimCostTime)
	}

	if victimTxCallErr != nil {
		result["error"] = "victimTxCallErr"
		result["reason"] = victimTxCallErr.Error()
		result["amountIn"] = amountIn.String()
		return result
	}
	if len(victimTxCallResult.Revert()) > 0 {
		result["error"] = "execution_victimTx_reverted"
		result["reason"] = victimTxCallResult.Err.Error()
		result["amountIn"] = amountIn.String()
		return result
	}
	if victimTxCallResult.Err != nil {
		result["error"] = "execution_victimTx_callResult_err"
		result["reason"] = victimTxCallResult.Err.Error()
		result["amountIn"] = amountIn.String()
		return result
	}

	// 跟跑----------------------------------------------------------------------------------------
	backStartTime := time.Now()
	backAmountOut, bErr := execute(ctx, reqAndIndex, false, sbp, frontAmountOut, statedb, s, head)
	backCostTime := time.Since(backStartTime).Milliseconds()

	if sbp.LogEnable {
		log.Info("call_execute_back", "reqAndIndex", reqAndIndex, "backAmountIn", frontAmountOut, "backAmountOut", backAmountOut, "bErr", bErr, "cost_time", backCostTime)
	}
	if bErr != nil || backAmountOut.Cmp(big.NewInt(0)) == 0 {
		result["error"] = "backCallErr"
		result["reason"] = bErr.Error()
		result["amountIn"] = amountIn.String()
		result["frontAmountOut"] = frontAmountOut.String()
		return result
	}
	profit := new(big.Int).Sub(backAmountOut, amountIn)

	result["amountIn"] = amountIn
	result["frontAmountOut"] = frontAmountOut
	result["amountOut"] = backAmountOut
	result["profit"] = profit

	if profit.Cmp(big.NewInt(0)) <= 0 {
		result["error"] = "profit_too_low"
		result["reason"] = errors.New("profit_too_low")
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
	head *types.Header) (*big.Int, error) {

	var data []byte

	if sbp.LogEnable {
		log.Info("call_execute1", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}
	if isFront {

		if sbp.BuyOrSale {
			data = encodeParams(sbp.Version2, sbp.Token2, sbp.Token3, sbp.PairOrPool2, sbp.Fee2, sbp.ZeroForOne2, amountIn, sbp.BriberyAddress, sbp.AmountOutMin)
		} else {
			data = encodeParamsSale(sbp.Token1, sbp.Token2, sbp.Token3, sbp.PairOrPool1, sbp.Fee1, sbp.ZeroForOne1, sbp.PairOrPool2, sbp.Fee2, sbp.ZeroForOne2, amountIn, sbp.BriberyAddress, sbp.AmountOutMin)
		}

	} else {

		if sbp.BuyOrSale {
			data = encodeParams(sbp.Version2, sbp.Token3, sbp.Token2, sbp.PairOrPool2, sbp.Fee2, !sbp.ZeroForOne2, amountIn, sbp.BriberyAddress, sbp.AmountOutMin)
		} else {
			data = encodeParamsSale(sbp.Token3, sbp.Token2, sbp.Token1, sbp.PairOrPool2, sbp.Fee2, !sbp.ZeroForOne2, sbp.PairOrPool1, sbp.Fee1, !sbp.ZeroForOne1, amountIn, sbp.BriberyAddress, sbp.AmountOutMin)
		}
	}

	if sbp.LogEnable {
		log.Info("call_execute2", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "data_hex", common.Bytes2Hex(data))
	}
	bytes := hexutil.Bytes(data)
	callArgs := TransactionArgs{
		From: &sbp.Eoa,
		To:   &sbp.Contract,
		Data: &bytes,
	}

	reqIdString := reqId + amountIn.String()

	callResult, err := mevCall(reqIdString, sdb, head, s, ctx, callArgs, nil, nil)
	if sbp.LogEnable {
		log.Info("call_execute3", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", err, "callResult", callResult)
	}
	if callResult != nil {

		if sbp.LogEnable {
			log.Info("call_execute4", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "result", string(callResult.ReturnData))
		}
		var revertReason *revertError
		if len(callResult.Revert()) > 0 {

			revertReason = newRevertError(callResult)
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
			return nil, revertReason
		}
	}
	if err != nil {
		if sbp.LogEnable {
			log.Info("call_execute6", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", err)
		}
		return nil, err
	}
	if callResult.Err != nil {
		if sbp.LogEnable {
			log.Info("call_execute7", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", callResult.Err)
		}
		return nil, callResult.Err
	}
	amountOut := new(big.Int).SetBytes(callResult.Return())
	if sbp.LogEnable {
		log.Info("call_execute8", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "amountOut", amountOut.String())
	}
	return amountOut, nil
}

func encodeParamsSale(
	token1 common.Address,
	token2 common.Address,
	token3 common.Address,
	pairOrPool1 common.Address,
	fee1 *big.Int,
	zeroForOne1 bool,

	pairOrPool2 common.Address,
	fee2 *big.Int,
	zeroForOne2 bool,
	amountIn *big.Int,
	briberyAddress common.Address,
	amountOutMin *big.Int,
) []byte {
	params := make([]byte, 0)
	params = append(params, []byte{0x00, 0x00, 0x00, 0x00}...)
	params = append(params, fillBytes(14, amountIn.Bytes())...)
	params = append(params, token1.Bytes()...)
	params = append(params, token2.Bytes()...)
	params = append(params, token3.Bytes()...)
	params = append(params, fillBytes(2, fee1.Bytes())...)
	params = append(params, pairOrPool1.Bytes()...)
	if zeroForOne1 {
		params = append(params, []byte{1}...)
	} else {
		params = append(params, []byte{0}...)
	}
	params = append(params, fillBytes(2, fee2.Bytes())...)
	params = append(params, pairOrPool2.Bytes()...)
	if zeroForOne2 {
		params = append(params, []byte{1}...)
	} else {
		params = append(params, []byte{0}...)
	}
	params = append(params, fillBytes(14, amountOutMin.Bytes())...)
	params = append(params, briberyAddress.Bytes()...)
	return params
}

func encodeParams(
	version int,
	tokenIn common.Address,
	tokenOut common.Address,
	pairOrPool common.Address,

	fee *big.Int,
	zeroForOne bool,
	amountIn *big.Int,
	briberyAddress common.Address,
	amountOutMin *big.Int,
) []byte {
	params := make([]byte, 0)
	if version == V2 {
		params = append(params, []byte{0xa9, 0x24, 0x83, 0xf0}...)
	} else {
		params = append(params, []byte{0x2f, 0xb4, 0x2d, 0x70}...)
	}
	params = append(params, fillBytes(14, amountIn.Bytes())...)
	params = append(params, pairOrPool.Bytes()...)
	params = append(params, tokenIn.Bytes()...)
	params = append(params, tokenOut.Bytes()...)
	params = append(params, briberyAddress.Bytes()...)
	params = append(params, fillBytes(14, amountOutMin.Bytes())...)
	if version == V2 {
		params = append(params, fillBytes(2, fee.Bytes())...)
	}
	if zeroForOne {
		params = append(params, []byte{1}...)
	} else {
		params = append(params, []byte{0}...)
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

func mevCall(reqId string, state *state.StateDB, header *types.Header, s *BundleAPI, ctx context.Context, args TransactionArgs, overrides *StateOverride, blockOverrides *BlockOverrides) (*core.ExecutionResult, error) {

	defer func(start time.Time) {
		log.Info("call_ExecutingEVMCallFinished", "runtime", time.Since(start), "reqId", reqId)
	}(time.Now())
	//result, err := doMevCall(ctx, s.b, args, state, header, overrides, blockOverrides, s.b.RPCEVMTimeout(), s.b.RPCGasCap())
	result, err := doMevCall(ctx, s.b, args, state, header, overrides, blockOverrides, 50*time.Millisecond, s.b.RPCGasCap())

	if err != nil {
		return nil, err
	}
	// If the result contains a revert reason, try to unpack and return it.
	if len(result.Revert()) > 0 {
		return nil, newRevertError(result)
	}
	return result, result.Err
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

func timeCost(reqId string, start time.Time) {
	tc := time.Since(start)
	log.Info("call_cost", "reqId", reqId, "ms", tc.Milliseconds())
}

func ApplyTransactionWithResult(config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, *core.ExecutionResult, error) {
	msg, err := core.TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := core.NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	return applyTransactionWithResult(msg, config, bc, author, gp, statedb, header, tx, usedGas, vmenv)
}

// apply transaction returning result, for callBundle
func applyTransactionWithResult(msg *core.Message, config *params.ChainConfig, bc core.ChainContext, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, *core.ExecutionResult, error) {
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
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
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

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), header.Number.Uint64(), header.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = header.Hash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, result, err
}
