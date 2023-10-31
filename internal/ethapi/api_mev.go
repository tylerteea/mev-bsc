package ethapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"math/big"
	"strings"
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

var (
	simulateAddress = common.HexToAddress("0x9Dc590b1CD86cA5c4035DcDd8dfDD1ac2DB5480b")
	simulateAbi, _  = abi.JSON(strings.NewReader(abiStr))

	steps = big.NewInt(50)
)

const abiStr = `[
    {
      "inputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_tokenIn",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_sandwich",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_target",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "_frontSize",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_backSize",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_targetSize",
          "type": "uint256"
        },
        {
          "internalType": "bytes",
          "name": "_frontParma",
          "type": "bytes"
        },
        {
          "internalType": "bytes",
          "name": "_backParma",
          "type": "bytes"
        },
        {
          "internalType": "bytes",
          "name": "_targetParam",
          "type": "bytes"
        }
      ],
      "name": "Simulate",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "amountOut",
          "type": "uint256"
        }
      ],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address[]",
          "name": "_operators",
          "type": "address[]"
        }
      ],
      "name": "addOperators",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "confirmOwner",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "operators",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "owner",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address[]",
          "name": "_operators",
          "type": "address[]"
        }
      ],
      "name": "removeOperators",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_newOwner",
          "type": "address"
        }
      ],
      "name": "updateOwner",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address[]",
          "name": "tokens",
          "type": "address[]"
        }
      ],
      "name": "withdraw",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "stateMutability": "payable",
      "type": "receive"
    }
  ],`

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
		state.Prepare(rules, from, header.Coinbase, tx.To(), vm.ActivePrecompiles(rules), tx.AccessList())

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

func (s *BundleAPI) simulate(ctx context.Context, pair common.Address, tokenIn common.Address, tokenOut common.Address, amountIn *big.Int, zeroForOne bool, gasLimit uint64, fee int64, wallet common.Address, victimTx *types.Transaction) []map[string]interface{} {

	head := s.chain.CurrentHeader()
	blockNo := s.bcapi.BlockNumber()
	number := rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(blockNo))
	stateDB, _, _ := s.b.StateAndHeaderByNumberOrHash(ctx, number)

	// todo 获取不同币的余额  待讨论
	balance := stateDB.GetBalance(wallet)
	nonce := stateDB.GetNonce(wallet)
	gasPrice := victimTx.GasPrice()
	// todo 郭鹏传
	//gasPrice := big.NewInt(params.3GWei)

	//计算出每次步长
	stepAmount := new(big.Int).Quo(new(big.Int).SetInt64(0).Sub(balance, amountIn), steps)

	//初始化整个执行ladder结构
	var ladder []*big.Int
	for amountIn.Cmp(balance) < 0 {
		ladder = append(ladder, new(big.Int).Set(amountIn))
		//累加
		amountIn = new(big.Int).Add(amountIn, stepAmount)
	}

	var results []map[string]interface{}
	var wg = new(sync.WaitGroup)
	wg.Add(len(ladder))

	//循环当前ladder，并发执行模拟调用，并且记录结果
	for _, amountIn := range ladder {

		go func(ctx context.Context, pair common.Address, amountIn *big.Int, tokenIn, tokenOut common.Address, gasLimit uint64, gasPrice *big.Int, fee int64, zeroForOne bool, wallet common.Address, victimTx *types.Transaction) {
			//组装合约调用入参
			data, err := newData(pair, tokenIn, tokenOut, big.NewInt(fee), amountIn, gasLimit, gasPrice, zeroForOne, nonce, victimTx)
			if err != nil {
				return
			}

			fmt.Println(fmt.Sprintf("simulateAddress: %s , wallet: %s , blockNo: %d, txData: %s ", simulateAddress.String(), wallet.String(), blockNo, common.Bytes2Hex(data)))

			callMsg := ethereum.CallMsg{
				From:      wallet,
				To:        &simulateAddress,
				GasPrice:  gasPrice,
				GasFeeCap: gasPrice,
				GasTipCap: gasPrice,
				Data:      data,
			}

			//执行模拟合约
			callResult, err := callContract(s.chain, callMsg, head, stateDB)

			if err != nil || callResult.Err != nil || len(callResult.ReturnData) == 0 {
				return
			}
			//解析返回值，记录返回amountOut
			mapResult := make(map[string]interface{})
			_ = json.Unmarshal(callResult.ReturnData, &mapResult)

			amountOut2 := mapResult["amountOut"].(int)
			//如果执行成功，记录当前输入值
			result := make(map[string]interface{})
			result["tokenIn"] = tokenIn
			result["tokenOut"] = tokenOut
			result["amountIn"] = new(big.Int).Set(amountIn)
			result["amountOut"] = new(big.Int).SetInt64(int64(amountOut2))
			results = append(results, result)

			wg.Done()
		}(ctx, pair, amountIn, tokenIn, tokenOut, gasLimit, gasPrice, fee, zeroForOne, wallet, victimTx)
	}
	wg.Wait()
	return results
}

func callContract(blockChain *core.BlockChain, call ethereum.CallMsg, header *types.Header, stateDB *state.StateDB) (*core.ExecutionResult, error) {

	msg := &core.Message{
		From:              call.From,
		To:                call.To,
		Value:             call.Value,
		GasLimit:          call.Gas,
		GasPrice:          call.GasPrice,
		GasFeeCap:         call.GasFeeCap,
		GasTipCap:         call.GasTipCap,
		Data:              call.Data,
		AccessList:        call.AccessList,
		SkipAccountChecks: true,
	}

	sb := stateDB.Copy()

	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, blockChain, nil)
	vmEnv := vm.NewEVM(evmContext, txContext, sb, blockChain.Config(), vm.Config{NoBaseFee: true})
	gasPool := new(core.GasPool).AddGas(math.MaxUint64)

	return core.ApplyMessage(vmEnv, msg, gasPool)
}

func newData(
	pairAddress common.Address,
	tokenIn common.Address,
	tokenOut common.Address,
	fee *big.Int,
	amountIn *big.Int,
	gasLimit uint64,
	gasPrice *big.Int,
	zeroForOne bool,
	nonce uint64,
	victimTx *types.Transaction,
) ([]byte, error) {

	selector := simulateAbi.Methods["Simulate"].ID[:4]

	params := make([]byte, 0)
	params = append(params, selector...)
	params = append(params, fillBytes(14, amountIn.Bytes())...)
	params = append(params, pairAddress.Bytes()...)
	params = append(params, tokenIn.Bytes()...)
	params = append(params, tokenOut.Bytes()...)
	params = append(params, pairAddress.Bytes()...)
	params = append(params, fillBytes(14, big.NewInt(0).Bytes())...)
	params = append(params, fillBytes(2, fee.Bytes())...)
	if zeroForOne {
		params = append(params, []byte{1}...)
	} else {
		params = append(params, []byte{0}...)
	}
	params = append(params, fillBytes(14, big.NewInt(0).Bytes())...)

	frontTxData := types.NewTransaction(nonce, simulateAddress, big.NewInt(0), gasLimit, gasPrice, params)

	backTxData := types.NewTransaction(nonce+1, simulateAddress, big.NewInt(0), gasLimit, gasPrice, nil)

	victimSize := int64(len(victimTx.Data()))
	result, err := simulateAbi.Pack("Simulate", tokenIn, simulateAddress, victimTx.To(),
		new(big.Int).SetUint64(frontTxData.Size()), new(big.Int).SetUint64(backTxData.Size()),

		new(big.Int).SetInt64(victimSize), frontTxData.Data(), backTxData.Data(), victimTx.Data())

	return result, err
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
