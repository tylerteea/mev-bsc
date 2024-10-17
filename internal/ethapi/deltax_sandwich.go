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

type ContractResult struct {
	PathAmounts []*PathAmount
	Diff        *big.Int
}

type PathAmount struct {
	AmountIn  *big.Int
	AmountOut *big.Int
	Step      int
}

type SbpBuyArgs struct {
	Eoa                common.Address `json:"eoa"`
	Contract           common.Address `json:"contract"`
	Balance            *big.Int       `json:"balance"`
	Token2             common.Address `json:"token2"`
	Token3             common.Address `json:"token3"`
	PairOrPool2        common.Address `json:"pairOrPool2"`
	Router2            common.Address `json:"router2"`
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

type SbpSaleArgs struct {
	Eoa      common.Address `json:"eoa"`
	Contract common.Address `json:"contract"`
	Balance  *big.Int       `json:"balance"`

	Token1        common.Address `json:"token1"`
	Token2        common.Address `json:"token2"`
	Token3        common.Address `json:"token3"`
	PairOrPool1   common.Address `json:"pairOrPool1"`
	Router1       common.Address `json:"router1"`
	ZeroForOne1   bool           `json:"zeroForOne1"`
	Fee1          *big.Int       `json:"fee1"`
	Version1      int            `json:"version1"`
	PairOrPool2   common.Address `json:"pairOrPool2"`
	Router2       common.Address `json:"router2"`
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

type BuyConfig struct {
	Simulate      bool
	CheckTax      bool
	CalcAmountOut bool
	FeeToBuilder  bool
	ZeroForOne    int
}

func NewBuyConfig(checkTax bool, calcAmountOut bool, feeToBuilder bool, zeroForOne int) *BuyConfig {
	return &BuyConfig{
		Simulate:      Simulate,
		CheckTax:      checkTax,
		CalcAmountOut: calcAmountOut,
		FeeToBuilder:  feeToBuilder,
		ZeroForOne:    zeroForOne,
	}
}

type SaleConfig struct {
	IsBackRun     bool
	Simulate      bool
	CheckTax      bool
	CalcAmountOut bool
	FeeToBuilder  bool
}

func NewSaleConfig(isBackRun bool, checkTax bool, calcAmountOut bool, feeToBuilder bool) *SaleConfig {
	return &SaleConfig{
		IsBackRun:     isBackRun,
		Simulate:      Simulate,
		CheckTax:      checkTax,
		CalcAmountOut: calcAmountOut,
		FeeToBuilder:  feeToBuilder,
	}
}

type SaleOption struct {
	ZeroForOne2 int
	Version2    int
	ZeroForOne1 int
	Version1    int
}

func NewSaleOption(zeroForOne2 int, version2 int, zeroForOne1 int, version1 int) *SaleOption {
	return &SaleOption{
		ZeroForOne2: zeroForOne2,
		Version2:    version2,
		ZeroForOne1: zeroForOne1,
		Version1:    version1,
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}

func (s *BundleAPI) SandwichBestProfitMinimizeBuyNew(ctx context.Context, sbp SbpBuyArgs) map[string]interface{} {

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

	return s.SandwichBestProfitMinimizeSaleNew(ctx, sbpSaleArgs)
}

func (s *BundleAPI) SandwichBestProfitMinimizeSaleNew(ctx context.Context, sbp SbpSaleArgs) map[string]interface{} {

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

	nextBlockNum := new(big.Int).Add(head.Number, BigIntOne)

	if sbp.LogEnable {
		log.Info("call_sbp_4_", "reqId", reqId, "blockNumber", number.BlockNumber.Int64(), "number", head.Number, "hash", head.Hash(), "parentHash", head.ParentHash)
	}

	victimTxMsg, victimTxMsgErr := core.TransactionToMessage(victimTransaction, types.MakeSigner(s.b.ChainConfig(), head.Number, head.Time), head.BaseFee)

	if victimTxMsgErr != nil {
		result[errorString] = "victimTxMsgErr"
		result[reasonString] = victimTxMsgErr.Error()
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

		grossProfit, workErr := worker(ctx, head, nextBlockNum, victimBlockCtx, victimTxContext, victimTxMsg, sbp, s, reqId, stateDB, amountInInt)

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
		result[errorString] = "minimize_err"
		result[reasonString] = err.Error()
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
	workerResults := workerFinal(ctx, head, nextBlockNum, victimTransaction, sbp, s, reqAndIndex, sdb, quoteAmountIn)

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

func workerFinal(
	ctx context.Context,
	head *types.Header,
	nextBlockNum *big.Int,
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
	frontContractReturn, fErr := executeFinal(ctx, reqAndIndex, true, sbp, amountIn, statedb, s, head, nextBlockNum)

	if sbp.LogEnable {
		marshal, _ := json.Marshal(frontContractReturn)
		log.Info("call_execute_front", "reqAndIndex", reqAndIndex, "nextBlockNum", nextBlockNum, "amountIn", amountIn, "frontContractReturn", string(marshal), "fErr", fErr)
	}
	if fErr != nil {
		result[errorString] = "frontCallErr"
		result[reasonString] = fErr.Error()
		result[frontAmountInString] = amountIn.String()
		return result
	}

	// 受害者----------------------------------------------------------------------------------------
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

	backAmountIn := frontContractReturn.Diff
	// 跟跑----------------------------------------------------------------------------------------
	backContractReturn, bErr := executeFinal(ctx, reqAndIndex, false, sbp, backAmountIn, statedb, s, head, nextBlockNum)

	if sbp.LogEnable {
		marshal, _ := json.Marshal(backContractReturn)
		log.Info("call_execute_back", "reqAndIndex", reqAndIndex, "nextBlockNum", nextBlockNum, backAmountInString, backAmountIn, "backContractReturn", string(marshal), "bErr", bErr)
	}
	if bErr != nil {
		result[errorString] = "backCallErr"
		result[reasonString] = bErr.Error()
		result[frontAmountInString] = amountIn
		return result
	}

	if sbp.BuyOrSale && sbp.Version2 != V3 {
		backContractReturn.Diff = GetShortNumber(backContractReturn.Diff)
	}

	profit := new(big.Int).Sub(backContractReturn.Diff, frontContractReturn.PathAmounts[0].AmountIn)

	if sbp.BuyOrSale {
		result[front_amount_in_1] = frontContractReturn.PathAmounts[0].AmountIn
		result[front_amount_out_1] = frontContractReturn.PathAmounts[0].AmountOut
		result[front_diff] = frontContractReturn.Diff

		result[back_amount_in_1] = backContractReturn.PathAmounts[0].AmountIn
		result[back_amount_out_1] = backContractReturn.PathAmounts[0].AmountOut
		result[back_diff] = backContractReturn.Diff

	} else {
		result[front_amount_in_1] = frontContractReturn.PathAmounts[0].AmountIn
		result[front_amount_out_1] = frontContractReturn.PathAmounts[0].AmountOut
		result[front_amount_in_2] = frontContractReturn.PathAmounts[1].AmountIn
		result[front_amount_out_2] = frontContractReturn.PathAmounts[1].AmountOut
		result[front_diff] = frontContractReturn.Diff

		result[back_amount_in_1] = backContractReturn.PathAmounts[0].AmountIn
		result[back_amount_out_1] = backContractReturn.PathAmounts[0].AmountOut
		result[back_amount_in_2] = backContractReturn.PathAmounts[1].AmountIn
		result[back_amount_out_2] = backContractReturn.PathAmounts[1].AmountOut
		result[back_diff] = backContractReturn.Diff
	}

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

func worker(
	ctx context.Context,
	head *types.Header,
	nextBlockNum *big.Int,
	victimBlockCtx vm.BlockContext,
	victimTxCtx vm.TxContext,
	victimMsg *core.Message,
	sbp SbpSaleArgs,
	s *BundleAPI,
	reqAndIndex string,
	statedb *state.StateDB,
	amountIn *big.Int) (*big.Int, error) {

	// 抢跑----------------------------------------------------------------------------------------
	realFrontAmountIn, realFrontAmountOut, fErr := execute(ctx, reqAndIndex, true, sbp, amountIn, statedb, s, head, nextBlockNum)

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
	realBackAmountIn, realBackAmountOut, bErr := execute(ctx, reqAndIndex, false, sbp, backAmountIn, statedb, s, head, nextBlockNum)

	if sbp.LogEnable {
		log.Info("call_execute_back", "reqAndIndex", reqAndIndex, "nextBlockNum", nextBlockNum, backAmountInString, backAmountIn, "realBackAmountIn", realBackAmountIn, "realBackAmountOut", realBackAmountOut, "bErr", bErr)
	}
	if bErr != nil {
		return nil, bErr
	}

	if sbp.BuyOrSale && sbp.Version2 != V3 {
		realBackAmountOut = GetShortNumber(realBackAmountOut)
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

func execute(
	ctx context.Context,
	reqId string,
	isFront bool,
	sbp SbpSaleArgs,
	amountIn *big.Int,
	sdb *state.StateDB,
	s *BundleAPI,
	head *types.Header,
	nextBlockNum *big.Int,
) (*big.Int, *big.Int, error) {

	var data []byte

	if sbp.LogEnable {
		log.Info("call_execute1", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}

	if isFront {

		if sbp.BuyOrSale {

			amountIn = GetShortNumber(amountIn)
			// 模拟的时候都检查税，正式发不检查
			frontBuyConfig := NewBuyConfig(true, true, false, boolToInt(sbp.ZeroForOne2))
			frontMinTokenOutBalance := BigIntZeroValue

			data = encodeParamsBuyNew(sbp.Version2, true, amountIn, sbp.PairOrPool2, sbp.Router2, sbp.Token2, sbp.Token3, frontBuyConfig, sbp.Fee2, BigIntZeroValue, frontMinTokenOutBalance, sbp.BriberyAddress, BigIntZeroValue)
		} else {

			// 模拟的时候都检查税，正式发不检查
			frontSaleConfig := NewSaleConfig(!isFront, true, true, false)
			frontSaleOption := NewSaleOption(boolToInt(sbp.ZeroForOne2), sbp.Version2, boolToInt(sbp.ZeroForOne1), sbp.Version1)

			data = encodeParamsSaleNew(amountIn, BigIntZeroValue, BigIntZeroValue, BigIntZeroValue, sbp.PairOrPool1, sbp.Router1, sbp.PairOrPool2, sbp.Router2, sbp.Token1, sbp.Token2, sbp.Token3, frontSaleOption, frontSaleConfig, sbp.Fee1, sbp.Fee2, sbp.MinTokenOutBalance, sbp.BriberyAddress, BigIntZeroValue)
		}
	} else {

		if sbp.BuyOrSale {

			amountIn = GetShortNumber(amountIn)
			// 模拟的时候都检查税，正式发不检查
			backBuyConfig := NewBuyConfig(true, true, false, boolToInt(!sbp.ZeroForOne2))
			data = encodeParamsBuyNew(sbp.Version2, false, amountIn, sbp.PairOrPool2, sbp.Router2, sbp.Token3, sbp.Token2, backBuyConfig, sbp.Fee2, BigIntZeroValue, sbp.MinTokenOutBalance, sbp.BriberyAddress, BigIntZeroValue)
		} else {

			// 模拟的时候都检查税，正式发不检查
			backSaleConfig := NewSaleConfig(!isFront, true, true, false)
			backSaleOption := NewSaleOption(boolToInt(!sbp.ZeroForOne1), sbp.Version1, boolToInt(!sbp.ZeroForOne2), sbp.Version2)

			data = encodeParamsSaleNew(amountIn, BigIntZeroValue, BigIntZeroValue, BigIntZeroValue, sbp.PairOrPool2, sbp.Router2, sbp.PairOrPool1, sbp.Router1, sbp.Token3, sbp.Token2, sbp.Token1, backSaleOption, backSaleConfig, sbp.Fee2, sbp.Fee1, sbp.MinTokenOutBalance, sbp.BriberyAddress, BigIntZeroValue)
		}
	}

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

	lenR := len(callResult.Return())

	var diff *big.Int

	if sbp.BuyOrSale {
		if lenR == 64 {
			diff = new(big.Int).SetBytes(callResult.Return()[32:64])
			return amountIn, diff, nil
		}
	} else {
		if lenR == 160 {
			diff = new(big.Int).SetBytes(callResult.Return()[128:160])
			return amountIn, diff, nil
		}
	}

	if sbp.LogEnable {
		log.Info("call_execute11_结果数据长度检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR)
	}
	return nil, nil, errors.New("结果数据长度检验不通过2")
}

func executeFinal(ctx context.Context,
	reqId string,
	isFront bool,
	sbp SbpSaleArgs,
	amountIn *big.Int,
	sdb *state.StateDB,
	s *BundleAPI,
	head *types.Header,
	nextBlockNum *big.Int,
) (*ContractResult, error) {

	var data []byte

	if sbp.LogEnable {
		log.Info("call_execute1", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}

	briberyWei := BigIntZeroValue

	if isFront {

		if sbp.BuyOrSale {

			amountIn = GetShortNumber(amountIn)
			// 模拟的时候都检查税，正式发不检查
			frontBuyConfig := NewBuyConfig(true, true, false, boolToInt(sbp.ZeroForOne2))
			frontMinTokenOutBalance := BigIntZeroValue

			data = encodeParamsBuyNew(sbp.Version2, true, amountIn, sbp.PairOrPool2, sbp.Router2, sbp.Token2, sbp.Token3, frontBuyConfig, sbp.Fee2, BigIntZeroValue, frontMinTokenOutBalance, sbp.BriberyAddress, briberyWei)
		} else {

			// 模拟的时候都检查税，正式发不检查
			frontSaleConfig := NewSaleConfig(!isFront, true, true, false)
			frontSaleOption := NewSaleOption(boolToInt(sbp.ZeroForOne2), sbp.Version2, boolToInt(sbp.ZeroForOne1), sbp.Version1)

			data = encodeParamsSaleNew(amountIn, BigIntZeroValue, BigIntZeroValue, BigIntZeroValue, sbp.PairOrPool1, sbp.Router1, sbp.PairOrPool2, sbp.Router2, sbp.Token1, sbp.Token2, sbp.Token3, frontSaleOption, frontSaleConfig, sbp.Fee1, sbp.Fee2, sbp.MinTokenOutBalance, sbp.BriberyAddress, briberyWei)
		}
	} else {

		if sbp.BuyOrSale {

			amountIn = GetShortNumber(amountIn)
			// 模拟的时候都检查税，正式发不检查
			backBuyConfig := NewBuyConfig(true, true, false, boolToInt(!sbp.ZeroForOne2))
			data = encodeParamsBuyNew(sbp.Version2, false, amountIn, sbp.PairOrPool2, sbp.Router2, sbp.Token3, sbp.Token2, backBuyConfig, sbp.Fee2, BigIntZeroValue, sbp.MinTokenOutBalance, sbp.BriberyAddress, briberyWei)
		} else {

			// 模拟的时候都检查税，正式发不检查
			backSaleConfig := NewSaleConfig(!isFront, true, true, false)
			backSaleOption := NewSaleOption(boolToInt(!sbp.ZeroForOne1), sbp.Version1, boolToInt(!sbp.ZeroForOne2), sbp.Version2)

			data = encodeParamsSaleNew(amountIn, BigIntZeroValue, BigIntZeroValue, BigIntZeroValue, sbp.PairOrPool2, sbp.Router2, sbp.PairOrPool1, sbp.Router1, sbp.Token3, sbp.Token2, sbp.Token1, backSaleOption, backSaleConfig, sbp.Fee2, sbp.Fee1, sbp.MinTokenOutBalance, sbp.BriberyAddress, briberyWei)
		}
	}

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

	lenR := len(callResult.Return())
	if sbp.LogEnable {
		log.Info("call_execute80_结果数据长度", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR)
	}

	var contractResult *ContractResult

	if sbp.BuyOrSale {
		if lenR == 64 {

			amountOut := new(big.Int).SetBytes(callResult.Return()[:32])
			diff := new(big.Int).SetBytes(callResult.Return()[32:64])

			if diff.Cmp(BigIntZeroValue) <= 0 {
				if sbp.LogEnable {
					log.Info("call_execute8_买结果数据diff检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR, "amountOut", amountOut, "diff", diff)
				}
				return nil, errors.New("买结果数据diff检验不通过1")
			}

			if sbp.Version2 != V3 {
				if amountOut.Cmp(BigIntZeroValue) <= 0 {
					if sbp.LogEnable {
						log.Info("call_execute8_v2买结果数据大小检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR, "amountOut", amountOut, "diff", diff)
					}
					return nil, errors.New("v2买结果数据大小检验不通过1")
				}
			}

			pathAmount := &PathAmount{
				AmountIn:  amountIn,
				AmountOut: amountOut,
				Step:      1,
			}
			contractResult = &ContractResult{
				PathAmounts: []*PathAmount{pathAmount},
				Diff:        diff,
			}
		} else {
			if sbp.LogEnable {
				log.Info("call_execute9_买结果数据大小检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR)
			}
			return nil, errors.New("买结果数据长度检验不通过2")
		}
	} else {

		if lenR == 160 {
			amountIn1 := new(big.Int).SetBytes(callResult.Return()[:32])
			amountOut1 := new(big.Int).SetBytes(callResult.Return()[32:64])
			amountIn2 := new(big.Int).SetBytes(callResult.Return()[64:96])
			amountOut2 := new(big.Int).SetBytes(callResult.Return()[96:128])
			diff := new(big.Int).SetBytes(callResult.Return()[128:160])

			if sbp.Version1 != V3 {
				if amountOut1.Cmp(BigIntZeroValue) <= 0 {
					if sbp.LogEnable {
						log.Info("call_execute10_卖结果数据amountOut1大小检验不通过1",
							"reqId", reqId,
							"amountIn", amountIn,
							"isFront", isFront,
							"callResult_len", lenR,
							"amountIn1", amountIn1,
							"amountOut1", amountOut1,
							"amountIn2", amountIn2,
							"amountOut2", amountOut2,
							"diff", diff,
						)
					}
					return nil, errors.New("卖结果数据amountOut1大小检验不通过1")
				}
			} else {
				if amountOut1.Cmp(BigIntZeroValue) < 0 {
					if sbp.LogEnable {
						log.Info("call_execute10_卖结果数据amountOut1大小检验不通过2",
							"reqId", reqId,
							"amountIn", amountIn,
							"isFront", isFront,
							"callResult_len", lenR,
							"amountIn1", amountIn1,
							"amountOut1", amountOut1,
							"amountIn2", amountIn2,
							"amountOut2", amountOut2,
							"diff", diff,
						)
					}
					return nil, errors.New("卖结果数据amountOut1大小检验不通过2")
				}
			}

			if sbp.Version2 != V3 {
				if amountOut2.Cmp(BigIntZeroValue) <= 0 {
					if sbp.LogEnable {
						log.Info("call_execute10_卖结果数据amountOut2大小检验不通过1",
							"reqId", reqId,
							"amountIn", amountIn,
							"isFront", isFront,
							"callResult_len", lenR,
							"amountIn1", amountIn1,
							"amountOut1", amountOut1,
							"amountIn2", amountIn2,
							"amountOut2", amountOut2,
							"diff", diff,
						)
					}
					return nil, errors.New("卖结果数据amountOut2大小检验不通过1")
				}
			} else {
				if amountOut2.Cmp(BigIntZeroValue) < 0 {
					if sbp.LogEnable {
						log.Info("call_execute10_卖结果数据amountOut2大小检验不通过2",
							"reqId", reqId,
							"amountIn", amountIn,
							"isFront", isFront,
							"callResult_len", lenR,
							"amountIn1", amountIn1,
							"amountOut1", amountOut1,
							"amountIn2", amountIn2,
							"amountOut2", amountOut2,
							"diff", diff,
						)
					}
					return nil, errors.New("卖结果数据amountOut2大小检验不通过2")
				}
			}

			if amountIn1.Cmp(BigIntZeroValue) <= 0 || amountIn2.Cmp(BigIntZeroValue) <= 0 || diff.Cmp(BigIntZeroValue) <= 0 {
				if sbp.LogEnable {
					log.Info("call_execute10_卖结果数据大小检验不通过",
						"reqId", reqId,
						"amountIn", amountIn,
						"isFront", isFront,
						"callResult_len", lenR,
						"amountIn1", amountIn1,
						"amountOut1", amountOut1,
						"amountIn2", amountIn2,
						"amountOut2", amountOut2,
						"diff", diff,
					)
				}
				return nil, errors.New("卖结果数据大小检验不通过1")
			}

			pathAmount1 := &PathAmount{
				AmountIn:  amountIn, //不使用amountIn1,因为返回的是减1的，使用原始的amountIn
				AmountOut: amountOut1,
				Step:      1,
			}
			pathAmount2 := &PathAmount{
				AmountIn:  amountIn2,
				AmountOut: amountOut2,
				Step:      2,
			}

			contractResult = &ContractResult{
				PathAmounts: []*PathAmount{pathAmount1, pathAmount2},
				Diff:        diff,
			}
		} else {
			if sbp.LogEnable {
				log.Info("call_execute11_卖结果数据长度检验不通过", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "callResult_len", lenR)
			}
			return nil, errors.New("卖结果数据长度检验不通过2")
		}
	}
	if sbp.LogEnable {
		log.Info("call_execute20", "reqId", reqId, "amountIn", amountIn, "isFront", isFront)
	}

	if contractResult == nil {
		return nil, errors.New("获取合约结果失败")
	}
	return contractResult, nil
}
