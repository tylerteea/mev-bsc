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
	"github.com/ethereum/go-ethereum/rpc"
	"math"
	"math/big"
	"runtime/debug"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"gonum.org/v1/gonum/optimize"
)

type (
	SbpArgs struct {
		CommonPathInfos []*CommonPathInfo `json:"commonPathInfos"`
		Eoa             common.Address    `json:"eoa"`
		Contract        common.Address    `json:"contract"`
		Balance         *big.Int          `json:"balance"`
		AmountInMin     *big.Int          `json:"amountInMin"`
		VictimTxHash    common.Hash       `json:"vTxHash"`

		ReqId           string  `json:"reqId"`
		FuncEvaluations int     `json:"funcEvaluations"`
		RunTimeout      int     `json:"runTimeout"`
		Iterations      int     `json:"iterations"`
		Concurrent      int     `json:"concurrent"`
		InitialValues   float64 `json:"initialValues"`
		LogEnable       bool    `json:"logEnable"`
	}
)

func (s *BundleAPI) SandwichBestProfit(ctx context.Context, sbp SbpArgs) *CombinationProfit {

	now := time.Now()
	reqId := sbp.ReqId
	defer timeCost(reqId, now)

	if sbp.LogEnable {
		req, _ := json.Marshal(sbp)
		log.Info("call_sbp_start", "reqId", reqId, "sbp", string(req))
	}

	result := &CombinationProfit{
		Error:  defaultError,
		Reason: defaultError,
	}

	timeout := s.b.RPCEVMTimeout()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	defer cancel()
	defer func(results *CombinationProfit) {
		if r := recover(); r != nil {
			if sbp.LogEnable {
				oldResultJson, _ := json.Marshal(result)
				log.Info("call_sbp_old_result_", "reqId", reqId, "result", string(oldResultJson))
			}
			result.Error = "panic"
			result.Reason = "panic"
			if sbp.LogEnable {
				newResultJson, _ := json.Marshal(result)
				log.Info("call_sbp_defer_result_", "reqId", reqId, "result", string(newResultJson))
			}
		}
	}(result)

	if sbp.Balance.Cmp(BigIntZeroValue) == 0 {
		result.Error = "args_err"
		result.Reason = "balance_is_0"
		return result
	}
	balance := sbp.Balance

	minAmountIn := sbp.AmountInMin
	victimTxHash := sbp.VictimTxHash

	// 根据受害人tx hash  从内存池得到tx msg
	victimTransaction := s.b.GetPoolTransaction(victimTxHash)

	// 获取不到 直接返回
	if victimTransaction == nil {
		result.Error = "tx_is_nil"
		result.Reason = "tx_is_nil"
		if sbp.LogEnable {
			log.Info("call_sbp_2_", "reqId", reqId)
		}
		return result
	}

	number := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	stateDBNew, head, _ := s.b.StateAndHeaderByNumberOrHash(ctx, number)
	nextBlockNum := new(big.Int).Add(head.Number, BigIntOne)

	if sbp.LogEnable {
		log.Info("call_sbp_4_", "reqId", reqId, "nextBlockNum", nextBlockNum, "hash", head.Hash(), "parentHash", head.ParentHash)
	}

	victimTxMsg, victimTxMsgErr := core.TransactionToMessage(victimTransaction, types.MakeSigner(s.b.ChainConfig(), head.Number, head.Time), head.BaseFee)

	if victimTxMsgErr != nil {
		result.Error = "victimTxMsgErr"
		result.Reason = victimTxMsgErr.Error()
		return result
	}

	victimBlockCtx := core.NewEVMBlockContext(head, s.chain, nil)
	victimTxContext := core.NewEVMTxContext(victimTxMsg)

	bestInFunc := func(x []float64) float64 {
		defer func() {
			if err := recover(); err != nil {
				log.Error(fmt.Sprintf("call_sandwichBestProfitMinimize_bestInFunc x[0]:%v, err:%v", x[0], err))
			}
		}()
		amountInFloat := x[0]
		if amountInFloat < 0 {
			if sbp.LogEnable {
				log.Info("call_sbp_6", "reqId", reqId, "amountInFloat", amountInFloat)
			}
			return 0.0 - amountInFloat
		}
		if sbp.LogEnable {
			log.Info("call_sbp_7", "reqId", reqId, "amountInFloat", amountInFloat)
		}

		floatIn := big.NewFloat(amountInFloat)
		amountIn := floatIn.Mul(floatIn, power18)

		amountInInt := new(big.Int)
		amountIn.Int(amountInInt)

		if amountInInt.Cmp(balance) > 0 {
			if sbp.LogEnable {
				log.Info("call_sbp_8", "reqId", reqId, "amountInFloat", amountInFloat)
			}
			f, _ := amountIn.Float64()
			return f
		}
		if amountInInt.Cmp(minAmountIn) < 0 {
			if sbp.LogEnable {
				log.Info("call_sbp_9", "reqId", reqId, "amountInFloat", amountInFloat)
			}
			sub, _ := amountInInt.Sub(minAmountIn, amountInInt).Float64()
			return sub
		}
		stateDB := stateDBNew.Copy()

		grossProfit, workErr := workerNew(ctx, head, nextBlockNum, victimBlockCtx, victimTxContext, victimTxMsg, sbp, s, reqId, stateDB, amountInInt)

		if sbp.LogEnable {
			reqIdMiniMize := reqId + "_" + amountInInt.String()
			log.Info("call_worker_minimize_result_end", "reqId", reqIdMiniMize, "amountIn", amountInInt, "grossProfit", grossProfit, "err", workErr)
		}
		if workErr == nil && grossProfit != nil {
			profitFloat, _ := grossProfit.Float64()
			return 0.0 - profitFloat
		}
		if sbp.LogEnable {
			log.Info("call_sbp_12", "reqId", reqId, "amountInFloat", amountInFloat)
		}
		f, _ := amountIn.Float64()
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

	resJson, _ := json.Marshal(res)
	log.Info("call_sbp_minimize_result", "reqId", reqId, "result", string(resJson))

	if err != nil {
		result.Error = "minimize_err"
		result.Reason = err.Error()
		if sbp.LogEnable {
			resultJson, _ := json.Marshal(result)
			log.Info("call_sbp_minimize_err", "reqId", reqId, "result", string(resultJson))
		}
		return result
	}

	x := res.X[0]
	floatX := big.NewFloat(x)
	maxProfitAmountIn := floatX.Mul(floatX, power18)
	quoteAmountIn := new(big.Int)
	maxProfitAmountIn.Int(quoteAmountIn)

	//大于等于0的过滤掉
	f := res.F

	if quoteAmountIn.Cmp(balance) > 0 || quoteAmountIn.Cmp(minAmountIn) < 0 || f >= 0 {
		result.Error = "minimize_result_out_of_limit"
		result.Reason = quoteAmountIn.String()
		if sbp.LogEnable {
			resultJson, _ := json.Marshal(result)
			log.Info("call_sbp_minimize_out_of_limit", "reqId", reqId, "result", string(resultJson))
		}
		return result
	}

	reqAndIndex := reqId + "_end"

	sdb := stateDBNew.Copy()
	workerResults := workerFinalNew(ctx, head, nextBlockNum, victimTransaction, sbp, s, reqAndIndex, sdb, quoteAmountIn)

	if sbp.LogEnable {
		marshal, _ := json.Marshal(workerResults)
		log.Info("call_worker_result_end", "reqId", reqAndIndex, "amountInReal", quoteAmountIn, "result", string(marshal))
	}

	if workerResults.Error == "" && workerResults.GrossProfit != nil {
		if workerResults.GrossProfit.Cmp(BigIntZeroValue) > 0 {
			result = workerResults
		}
	}
	if sbp.LogEnable {
		resultJson, _ := json.Marshal(result)
		log.Info("call_sbp_end", "reqId", reqId, "blockNumber", number.BlockNumber.Int64(), "result", string(resultJson), "cost_time(ms)", time.Since(now).Milliseconds())
	}
	return result
}

func workerFinalNew(ctx context.Context, head *types.Header, nextBlockNum *big.Int, victimTransaction *types.Transaction, sbp SbpArgs, s *BundleAPI, reqAndIndex string, statedb *state.StateDB, amountIn *big.Int) *CombinationProfit {

	defer func() {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...call_SandwichBestProfit", "reqAndIndex", reqAndIndex, "err", r, "stack", dss)
		}
	}()

	combinationProfit := &CombinationProfit{
		Error:  defaultError,
		Reason: defaultError,
	}

	// 抢跑----------------------------------------------------------------------------------------
	frontAmountInfo, frontDiff, fErr := executeFinalNew(ctx, reqAndIndex, true, sbp, amountIn, statedb, s, head, nextBlockNum)

	if sbp.LogEnable {
		marshal, _ := json.Marshal(frontAmountInfo)
		log.Info("call_execute_front", "reqAndIndex", reqAndIndex, "nextBlockNum", nextBlockNum, "amountIn", amountIn, "frontContractReturn", string(marshal), "frontDiff", frontDiff, "fErr", fErr)
	}
	if fErr != nil {
		combinationProfit.Error = "frontCallErr"
		combinationProfit.Reason = fErr.Error()
		return combinationProfit
	}

	// 受害者----------------------------------------------------------------------------------------
	victimTxMsg, victimTxMsgErr := core.TransactionToMessage(victimTransaction, types.MakeSigner(s.b.ChainConfig(), head.Number, head.Time), head.BaseFee)

	if victimTxMsgErr != nil {
		combinationProfit.Error = "victimTxMsgErr"
		combinationProfit.Reason = victimTxMsgErr.Error()
		return combinationProfit
	}

	evmContext := core.NewEVMBlockContext(head, s.chain, nil)
	victimTxContext := core.NewEVMTxContext(victimTxMsg)

	vmEnv := vm.NewEVM(evmContext, victimTxContext, statedb, s.chain.Config(), vm.Config{NoBaseFee: true})
	err := gopool.Submit(func() {
		<-ctx.Done()
		vmEnv.Cancel()
	})
	if err != nil {
		combinationProfit.Error = "victimPoolSubmit"
		combinationProfit.Reason = err.Error()
		return combinationProfit
	}
	gasPool := new(core.GasPool).AddGas(math.MaxUint64)
	victimTxCallResult, victimTxCallErr := core.ApplyMessage(vmEnv, victimTxMsg, gasPool)

	if victimTxCallErr != nil {
		combinationProfit.Error = "victimTxCallErr"
		combinationProfit.Reason = victimTxCallErr.Error()

		return combinationProfit
	}
	if len(victimTxCallResult.Revert()) > 0 {
		combinationProfit.Error = "execution_victimTx_reverted"
		combinationProfit.Reason = victimTxCallResult.Err.Error()

		return combinationProfit
	}
	if victimTxCallResult.Err != nil {
		combinationProfit.Error = "execution_victimTx_callResult_err"
		combinationProfit.Reason = victimTxCallResult.Err.Error()
		return combinationProfit
	}

	backAmountIn := frontDiff
	// 跟跑----------------------------------------------------------------------------------------
	backAmountInfo, backDiff, bErr := executeFinalNew(ctx, reqAndIndex, false, sbp, backAmountIn, statedb, s, head, nextBlockNum)

	if sbp.LogEnable {
		marshal, _ := json.Marshal(backAmountInfo)
		log.Info("call_execute_back", "reqAndIndex", reqAndIndex, "nextBlockNum", nextBlockNum, backAmountInString, backAmountIn, "backContractReturn", string(marshal), "backDiff", backDiff, "bErr", bErr)
	}
	if bErr != nil {
		combinationProfit.Error = "backCallErr"
		combinationProfit.Reason = bErr.Error()
		return combinationProfit
	}

	profit := new(big.Int).Sub(backDiff, frontAmountInfo[0].AmountIn)

	if profit.Cmp(BigIntZeroValue) <= 0 {
		combinationProfit.Error = "profit_too_low"
		combinationProfit.Reason = "profit_too_low"
		return combinationProfit
	}

	combinationProfit.Error = ""
	combinationProfit.Reason = ""

	combinationProfit.FrontAmountInfos = frontAmountInfo
	combinationProfit.FrontDiff = frontDiff
	combinationProfit.BackAmountInfos = backAmountInfo
	combinationProfit.BackDiff = backDiff

	if sbp.LogEnable {
		log.Info("call_execute_finish", "reqAndIndex", reqAndIndex)
	}
	return combinationProfit
}

func workerNew(
	ctx context.Context,
	head *types.Header,
	nextBlockNum *big.Int,
	victimBlockCtx vm.BlockContext,
	victimTxCtx vm.TxContext,
	victimMsg *core.Message,
	sbp SbpArgs,
	s *BundleAPI,
	reqAndIndex string,
	statedb *state.StateDB,
	amountIn *big.Int) (*big.Int, error) {

	// 抢跑----------------------------------------------------------------------------------------
	realFrontAmountIn, realFrontAmountOut, fErr := executeNew(ctx, reqAndIndex, true, sbp, amountIn, statedb, s, head, nextBlockNum)

	if sbp.LogEnable {
		log.Info("call_execute_front", "reqAndIndex", reqAndIndex, "nextBlockNum", nextBlockNum, "amountIn", amountIn, "frontAmountIn", realFrontAmountIn, "frontAmountOut", realFrontAmountOut, "fErr", fErr)
	}
	if fErr != nil {
		return nil, fErr
	}

	// 受害者----------------------------------------------------------------------------------------

	vmEnv := vm.NewEVM(victimBlockCtx, victimTxCtx, statedb, s.chain.Config(), vm.Config{NoBaseFee: true})
	err := gopool.Submit(func() {
		<-ctx.Done()
		vmEnv.Cancel()
	})
	if err != nil {
		return nil, err
	}
	gasPool := new(core.GasPool).AddGas(math.MaxUint64)
	victimTxCallResult, victimTxCallErr := core.ApplyMessage(vmEnv, victimMsg, gasPool)

	if victimTxCallErr != nil {
		return nil, victimTxCallErr
	}
	if len(victimTxCallResult.Revert()) > 0 {
		return nil, victimTxCallResult.Err
	}
	if victimTxCallResult.Err != nil {
		return nil, victimTxCallResult.Err
	}

	// 跟跑----------------------------------------------------------------------------------------
	backAmountIn := realFrontAmountOut
	realBackAmountIn, realBackAmountOut, bErr := executeNew(ctx, reqAndIndex, false, sbp, backAmountIn, statedb, s, head, nextBlockNum)

	if sbp.LogEnable {
		log.Info("call_execute_back", "reqAndIndex", reqAndIndex, "nextBlockNum", nextBlockNum, backAmountInString, backAmountIn, "realBackAmountIn", realBackAmountIn, "realBackAmountOut", realBackAmountOut, "bErr", bErr)
	}
	if bErr != nil {
		return nil, bErr
	}

	grossProfit := realBackAmountOut.Sub(realBackAmountOut, realFrontAmountIn)

	if grossProfit.Cmp(BigIntZeroValue) <= 0 {
		return nil, errors.New("profit_too_low")
	}

	if sbp.LogEnable {
		log.Info("call_execute_finish", "reqAndIndex", reqAndIndex)
	}
	return grossProfit, nil
}

func getSimulateHead() *ParamHead {
	globalConfig := globalConfigToBigInt(Simulate)
	strategy := SandwichBigIntZeroValue
	countSeq := SandwichBigIntZeroValue
	bundleId := SandwichBigIntZeroValue

	frontBuilder := SandwichBigIntZeroValue
	frontBribery := SandwichBigIntZeroValue
	frontParamHead := NewParamHead(frontBuilder, strategy, countSeq, globalConfig, bundleId, frontBribery)

	return frontParamHead
}

func getSimulateRouters(isFront bool, commonPathInfos []*CommonPathInfo, firstSwapAmountIn *big.Int) []*Router {

	pathLen := len(commonPathInfos)
	swapCount := big.NewInt(int64(pathLen))
	if isFront {

		var frontRouters []*Router
		var frontSwaps []*Swap
		for index := range commonPathInfos {

			commonPathInfo := commonPathInfos[index]

			amountIn := SandwichBigIntZeroValue
			if index == 0 {
				amountIn = firstSwapAmountIn
			}
			amountOut := SandwichBigIntZeroValue

			frontTokenIn := commonPathInfo.TokenIn
			frontTokenOut := commonPathInfo.TokenOut

			swap := NewSwap(frontTokenIn, commonPathInfo.PairsOrPool, commonPathInfo.ZeroForOne, commonPathInfo.Version, amountIn, amountOut, commonPathInfo.Fee, frontTokenOut)
			frontSwaps = append(frontSwaps, swap)
		}

		frontRouter := NewRouter(SandwichRouterType, swapCount, frontSwaps)
		frontRouters = append(frontRouters, frontRouter)

		return frontRouters
	} else {

		var backRouters []*Router
		var backSwaps []*Swap
		for index := range commonPathInfos {

			commonPathInfo := commonPathInfos[pathLen-1-index]

			amountIn := SandwichBigIntZeroValue
			if index == 0 {
				amountIn = firstSwapAmountIn
			}
			amountOut := SandwichBigIntZeroValue

			backTokenIn := commonPathInfo.TokenOut
			backTokenOut := commonPathInfo.TokenIn

			swap := NewSwap(backTokenIn, commonPathInfo.PairsOrPool, !commonPathInfo.ZeroForOne, commonPathInfo.Version, amountIn, amountOut, commonPathInfo.Fee, backTokenOut)
			backSwaps = append(backSwaps, swap)
		}

		backRouter := NewRouter(SandwichRouterType, swapCount, backSwaps)
		backRouters = append(backRouters, backRouter)

		return backRouters
	}
}

func executeNew(
	ctx context.Context,
	reqId string,
	isFront bool,
	sbp SbpArgs,
	amountIn *big.Int,
	sdb *state.StateDB,
	s *BundleAPI,
	head *types.Header,
	nextBlockNum *big.Int,
) (*big.Int, *big.Int, error) {

	if sbp.LogEnable {
		log.Info("call_execute1", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}

	//-----------token before balance ------------------------------------------------------------------------

	beginToken := NullAddress
	finalToken := NullAddress
	commonPathInfos := sbp.CommonPathInfos
	pathLen := len(commonPathInfos)

	if isFront {
		beginToken = commonPathInfos[0].TokenOut
		finalToken = commonPathInfos[pathLen-1].TokenOut
	} else {
		beginToken = commonPathInfos[pathLen-1].TokenOut
		finalToken = commonPathInfos[0].TokenOut
	}
	tokenBeforeBalance, tbErr := getERC20TokenBalance(ctx, s, finalToken, sbp.Contract, sdb, head)
	if tbErr != nil {
		return nil, nil, tbErr
	}
	amountInCost := SandwichBigIntZeroValue
	if finalToken.Cmp(beginToken) == 0 {
		amountInCost = amountIn
	}
	tokenBeforeBalance.Sub(tokenBeforeBalance, amountInCost)

	//-----------token before balance ------------------------------------------------------------------------

	paramHead := getSimulateHead()
	routers := getSimulateRouters(isFront, sbp.CommonPathInfos, amountIn)
	data := MakeParams(paramHead, nil, routers)

	if sbp.LogEnable {
		log.Info("call_execute2", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}

	bytes := hexutil.Bytes(data)
	callArgs := &TransactionArgs{
		From:  &sbp.Eoa,
		To:    &sbp.Contract,
		Data:  &bytes,
		Value: (*hexutil.Big)(nextBlockNum),
	}

	reqIdString := reqId + "_" + amountIn.String()

	callResult, err := mevCall(reqIdString, sdb, head, s, ctx, callArgs, nil, nil, nil)
	if sbp.LogEnable {
		log.Info("call_execute3", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", err, "callResult", callResult, "nextBlockNum", nextBlockNum, "data_hex", common.Bytes2Hex(data), "eoa", sbp.Eoa.String(), "contract", sbp.Contract.String())
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

	//-----------token after balance ------------------------------------------------------------------------
	tokenAfterBalance, tbErr := getERC20TokenBalance(ctx, s, finalToken, sbp.Contract, sdb, head)
	if tbErr != nil {
		if sbp.LogEnable {
			log.Info("call_execute8_tokenAfterBalance_err", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", tbErr)
		}
		return nil, nil, tbErr
	}
	//-----------token after balance ------------------------------------------------------------------------

	diff := tokenAfterBalance.Sub(tokenAfterBalance, tokenBeforeBalance)

	return amountIn, diff, nil
}

func executeFinalNew(ctx context.Context,
	reqId string,
	isFront bool,
	sbp SbpArgs,
	amountIn *big.Int,
	sdb *state.StateDB,
	s *BundleAPI,
	head *types.Header,
	nextBlockNum *big.Int,
) ([]*AmountInfo, *big.Int, error) {

	if sbp.LogEnable {
		log.Info("call_execute1", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}
	//-----------token before balance ------------------------------------------------------------------------

	beginToken := NullAddress
	finalToken := NullAddress
	commonPathInfos := sbp.CommonPathInfos
	pathLen := len(commonPathInfos)

	if isFront {
		beginToken = commonPathInfos[0].TokenOut
		finalToken = commonPathInfos[pathLen-1].TokenOut
	} else {
		beginToken = commonPathInfos[pathLen-1].TokenOut
		finalToken = commonPathInfos[0].TokenOut
	}
	tokenBeforeBalance, tbErr := getERC20TokenBalance(ctx, s, finalToken, sbp.Contract, sdb, head)
	if tbErr != nil {
		return nil, nil, tbErr
	}
	amountInCost := SandwichBigIntZeroValue
	if finalToken.Cmp(beginToken) == 0 {
		amountInCost = amountIn
	}
	tokenBeforeBalance.Sub(tokenBeforeBalance, amountInCost)

	//-----------token before balance ------------------------------------------------------------------------

	paramHead := getSimulateHead()
	routers := getSimulateRouters(isFront, sbp.CommonPathInfos, amountIn)
	data := MakeParams(paramHead, nil, routers)

	if sbp.LogEnable {
		log.Info("call_execute2", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}

	bytes := hexutil.Bytes(data)
	callArgs := &TransactionArgs{
		From:  &sbp.Eoa,
		To:    &sbp.Contract,
		Data:  &bytes,
		Value: (*hexutil.Big)(nextBlockNum),
	}

	reqIdString := reqId + "_" + amountIn.String()

	callResult, err := mevCall(reqIdString, sdb, head, s, ctx, callArgs, nil, nil, nil)
	if sbp.LogEnable {
		log.Info("call_execute3", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", err, "callResult", callResult, "nextBlockNum", nextBlockNum, "data_hex", common.Bytes2Hex(data), "eoa", sbp.Eoa.String(), "contract", sbp.Contract.String())
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

	//-----------token after balance ------------------------------------------------------------------------
	tokenAfterBalance, tbErr := getERC20TokenBalance(ctx, s, finalToken, sbp.Contract, sdb, head)
	if tbErr != nil {
		if sbp.LogEnable {
			log.Info("call_execute8_tokenAfterBalance_err", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "err", tbErr)
		}
		return nil, nil, tbErr
	}
	diff := tokenAfterBalance.Sub(tokenAfterBalance, tokenBeforeBalance)
	//-----------token after balance ------------------------------------------------------------------------

	wantLen := pathLen * 2 * NumberSize

	var swapInfos []*AmountInfo

	if lenR == wantLen {

		for i := 0; i < pathLen; i++ {
			m := (i + 1) * NumberSize
			n := (i + 2) * NumberSize
			amountInTmp := new(big.Int).SetBytes(callResult.Return()[:m])
			amountOutTmp := new(big.Int).SetBytes(callResult.Return()[m:n])

			swapInfo := &AmountInfo{
				AmountIn:  amountInTmp,
				AmountOut: amountOutTmp,
			}
			swapInfos = append(swapInfos, swapInfo)
		}
	} else {
		if sbp.LogEnable {
			log.Info("call_execute11_卖结果数据长度检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR)
		}
		return nil, nil, errors.New("卖结果数据长度检验不通过2")
	}
	if sbp.LogEnable {
		log.Info("call_execute20", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}
	return swapInfos, diff, nil
}
