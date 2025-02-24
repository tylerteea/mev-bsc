package ethapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"gonum.org/v1/gonum/optimize"
	"math"
	"math/big"
	"runtime/debug"
	"time"
)

var ApproveBytesGraFun = hexutil.Bytes(common.Hex2Bytes("095ea7b30000000000000000000000008341b19a2a602eae0f22633b6da12e1b016e6451000000000000000000000000000000000de0b6b3a7640014d1120d7b16000000"))

//----------------------------------GraFun-------------------------------------------------------------------------------

type SbpGraFunArgs struct {
	Eoa             common.Address `json:"eoa"`
	Contract        common.Address `json:"contract"`
	Balance         *big.Int       `json:"balance"`
	Token           common.Address `json:"token"`
	AmountInMin     *big.Int       `json:"amountInMin"`
	VictimTxHash    common.Hash    `json:"vTxHash"`
	ReqId           string         `json:"reqId"`
	FuncEvaluations int            `json:"funcEvaluations"`
	RunTimeout      int            `json:"runTimeout"`
	Iterations      int            `json:"iterations"`
	Concurrent      int            `json:"concurrent"`
	InitialValues   float64        `json:"initialValues"`
	LogEnable       bool           `json:"logEnable"`
}

// SandwichBestProfitGraFun profit calculate
func (s *BundleAPI) SandwichBestProfitGraFun(ctx context.Context, sbp SbpGraFunArgs) map[string]interface{} {

	result := make(map[string]interface{})

	result[errorString] = "default"
	result[reasonString] = "default"

	now := time.Now()

	reqId := sbp.ReqId

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

	if sbp.Balance.Cmp(BigIntZeroValue) == 0 {
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

	bestInFunc := func(x []float64) float64 {
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
			return 0.0 - amountInFloat
		}
		if sbp.LogEnable {
			log.Info("call_sbp_7", "reqId", reqId, "amountInFloat", amountInFloat)
		}

		amountIn := new(big.Float).SetFloat64(amountInFloat)
		amountIn.Mul(amountIn, Pow1018)

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
			sub, _ := amountInInt.Sub(minAmountIn, amountInInt).Float64()

			return sub
		}

		startTime := time.Now()
		stateDB := stateDBNew.Copy()
		workerResults := workerGraFun(ctx, head, victimTransaction, sbp, s, reqId, stateDB, amountInInt)
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
			if ok { // 让函数能够感知负值
				if sbp.LogEnable {
					log.Info("call_sbp_10", "reqId", reqId, "amountInFloat", amountInFloat)
				}
				profitFloat, _ := profit.Float64()
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

	//大于等于0的过滤掉
	f := res.F
	if f >= 0 {
		result[errorString] = "minimize_result_out_of_limit1"
		result[reasonString] = res.X[0]
		if sbp.LogEnable {
			resultJson, _ := json.Marshal(result)
			log.Info("call_sbp_minimize_out_of_limit", "reqId", reqId, "result", string(resultJson))
		}
		return result
	}

	x := res.X[0]
	maxProfitAmountIn := big.NewFloat(x)
	maxProfitAmountIn.Mul(maxProfitAmountIn, Pow1018)
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
	workerResults := workerGraFun(ctx, head, victimTransaction, sbp, s, reqAndIndex, sdb, quoteAmountIn)

	if sbp.LogEnable {
		marshal, _ := json.Marshal(workerResults)
		log.Info("call_worker_result_end", "reqId", reqAndIndex, "amountInReal", quoteAmountIn, "result", string(marshal))
	}

	if workerResults[errorString] == nil && workerResults[profitString] != nil {
		profit, ok := workerResults[profitString].(*big.Int)
		if ok && profit.Cmp(BigIntZeroValue) > 0 {
			result = workerResults
		}
	}
	if sbp.LogEnable {
		resultJson, _ := json.Marshal(result)
		log.Info("call_sbp_end", "reqId", reqId, "blockNumber", number.BlockNumber.Int64(), "result", string(resultJson), "cost_time(ms)", time.Since(now).Milliseconds())
	}
	return result
}

func workerGraFun(
	ctx context.Context,
	head *types.Header,
	victimTransaction *types.Transaction,
	sbp SbpGraFunArgs,
	s *BundleAPI,
	reqAndIndex string,
	statedb *state.StateDB,
	amountIn *big.Int,
) map[string]interface{} {

	defer func() {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...call_workerGraFun", "reqAndIndex", reqAndIndex, "err", r, "stack", dss)
		}
	}()

	result := make(map[string]interface{})

	eoaBalanceBefore := statedb.GetBalance(sbp.Eoa).ToBig()
	//-----------token balance before ------------------------------------------------------------------------
	//tokenBalanceBefore, tbErr := getERC20TokenBalance(ctx, s, sbp.Token, sbp.Eoa, statedb, head)
	//if tbErr != nil || tokenBalanceBefore == nil {
	//	result[errorString] = "get_token_balance_err"
	//	result[reasonString] = tbErr.Error()
	//	result[frontAmountInString] = amountIn.String()
	//	return result
	//}
	//
	//needApprove := true
	//if tokenBalanceBefore.Cmp(BigIntZeroValue) > 0 {
	//	needApprove = false
	//}

	// 抢跑----------------------------------------------------------------------------------------
	fErr := executeGraFun(ctx, reqAndIndex, true, sbp, amountIn, statedb, s, head)

	if sbp.LogEnable {
		log.Info("call_execute_front", "reqAndIndex", reqAndIndex, "amountIn", amountIn, "fErr", fErr)
	}
	if fErr != nil {
		result[errorString] = "frontCallErr"
		result[reasonString] = fErr.Error()
		result[frontAmountInString] = amountIn.String()
		return result
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

	vmEnv := vm.NewEVM(evmContext, statedb, s.chain.Config(), vm.Config{NoBaseFee: true})
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

	//approve  ------------------------------------------------------------------------------------------

	// 只有第一次才approve
	//if needApprove {
	approveCallArgs := &TransactionArgs{
		From: &sbp.Eoa,
		To:   &sbp.Token,
		Data: &ApproveBytesGraFun,
	}
	_, appErr := mevCall(reqAndIndex, statedb, head, s, ctx, approveCallArgs, nil, nil, nil)

	if sbp.LogEnable {
		log.Info("call_execute_approve", "reqAndIndex", reqAndIndex, "appErr", appErr)
	}

	if appErr != nil {
		result[errorString] = "approve_err"
		result[reasonString] = appErr.Error()
		result[frontAmountInString] = amountIn.String()
		return result
	}
	//}

	//-----------token balance ------------------------------------------------------------------------
	tokenBalance, tbErr := getERC20TokenBalance(ctx, s, sbp.Token, sbp.Eoa, statedb, head)
	if tbErr != nil || tokenBalance == nil || tokenBalance.Cmp(BigIntZeroValue) == 0 {
		result[errorString] = "get_token_balance_err"
		result[reasonString] = tbErr.Error()
		result[frontAmountInString] = amountIn.String()
		return result
	}

	// 跟跑----------------------------------------------------------------------------------------¬
	//backAmountIn := tokenBalance.Sub(tokenBalance, GweiOne)
	backAmountIn := tokenBalance

	bErr := executeGraFun(ctx, reqAndIndex, false, sbp, backAmountIn, statedb, s, head)
	eoaBalanceAfter := statedb.GetBalance(sbp.Eoa).ToBig()

	if sbp.LogEnable {
		log.Info("call_execute_back", "reqAndIndex", reqAndIndex, backAmountInString, backAmountIn, backAmountOutString, eoaBalanceAfter, "bErr", bErr)
	}
	if bErr != nil || eoaBalanceAfter.Cmp(BigIntZeroValue) <= 0 {
		result[errorString] = "backCallErr"
		result[reasonString] = bErr.Error()
		result[frontAmountInString] = amountIn
		result[frontAmountOutString] = backAmountIn
		return result
	}

	profit := new(big.Int).Sub(eoaBalanceAfter, eoaBalanceBefore)
	backAmountOut := new(big.Int).Add(amountIn, profit)

	result[frontAmountInString] = amountIn
	result[frontAmountOutString] = backAmountIn
	result[backAmountInString] = backAmountIn
	result[backAmountOutString] = backAmountOut
	result[profitString] = profit

	if profit.Cmp(BigIntZeroValue) <= 0 {
		result[errorString] = "profit_too_low"
		result[reasonString] = errors.New("profit_too_low")
	}

	if sbp.LogEnable {
		log.Info("call_execute_finish", "reqAndIndex", reqAndIndex)
	}
	return result
}

func executeGraFun(
	ctx context.Context,
	reqId string,
	isFront bool,
	sbp SbpGraFunArgs,
	amountIn *big.Int,
	sdb *state.StateDB,
	s *BundleAPI,
	head *types.Header) error {

	var callArgs *TransactionArgs

	if sbp.LogEnable {
		log.Info("call_execute1", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}
	if isFront {
		data := encodeParamsGraFunFront(sbp.Token, sbp.Eoa)
		value := (*hexutil.Big)(amountIn)
		bytes := hexutil.Bytes(data)
		callArgs = &TransactionArgs{
			From:  &sbp.Eoa,
			To:    &sbp.Contract,
			Data:  &bytes,
			Value: value,
		}
		if sbp.LogEnable {
			log.Info("call_execute2", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "value", value.String(), "data_hex", common.Bytes2Hex(data))
		}
	} else {
		data := encodeParamsGraFunBack(sbp.Token, amountIn, sbp.Eoa)
		bytes := hexutil.Bytes(data)
		callArgs = &TransactionArgs{
			From: &sbp.Eoa,
			To:   &sbp.Contract,
			Data: &bytes,
		}
		if sbp.LogEnable {
			log.Info("call_execute2", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "data_hex", common.Bytes2Hex(data))
		}
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
			return revertReason
		}
	}
	if err != nil {
		if sbp.LogEnable {
			log.Info("call_execute6", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", err)
		}
		return err
	}
	if callResult.Err != nil {
		if sbp.LogEnable {
			log.Info("call_execute7", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", callResult.Err)
		}
		return callResult.Err
	}

	if sbp.LogEnable {
		log.Info("call_execute20", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}
	return nil
}

func encodeParamsGraFunFront(
	tokenIn common.Address,
	eoa common.Address,
) []byte {

	//db61c76e
	params := []byte{0xdb, 0x61, 0xc7, 0x6e}

	params = append(params, FillBytes(32, tokenIn.Bytes())...)
	params = append(params, FillBytes(32, BigIntZeroValue.Bytes())...)
	params = append(params, FillBytes(32, eoa.Bytes())...)

	return params
}

func encodeParamsGraFunBack(
	token common.Address,
	amountIn *big.Int,
	eoa common.Address,
) []byte {

	//0x2dc8f867
	params := []byte{0x2d, 0xc8, 0xf8, 0x67}

	params = append(params, FillBytes(32, token.Bytes())...)
	params = append(params, FillBytes(32, amountIn.Bytes())...)
	params = append(params, FillBytes(32, BigIntZeroValue.Bytes())...)
	params = append(params, FillBytes(32, eoa.Bytes())...)

	return params
}
