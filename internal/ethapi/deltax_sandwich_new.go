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

// SandwichBestProfitMinimizeBuyNew profit calculate
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

// SandwichBestProfitMinimizeSaleNew profit calculate
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

	nextBlockNum := new(big.Int).Add(head.Number, BigIntOne)

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

		workerResults := workerNew(ctx, head, nextBlockNum, victimTransaction, sbp, s, reqId, stateDB, amountInInt)

		if sbp.LogEnable {
			log.Info("call_sbp_99", "reqId", reqId, "amountInFloat", amountInFloat)
		}

		if sbp.LogEnable {
			reqIdMiniMize := reqId + amountInInt.String()
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
	workerResults := workerNew(ctx, head, nextBlockNum, victimTransaction, sbp, s, reqAndIndex, sdb, quoteAmountIn)

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

func workerNew(
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
	frontContractReturn, fErr := executeNew(ctx, reqAndIndex, true, sbp, amountIn, statedb, s, head, nextBlockNum)

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
	backContractReturn, bErr := executeNew(ctx, reqAndIndex, false, sbp, backAmountIn, statedb, s, head, nextBlockNum)

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

func executeNew(
	ctx context.Context,
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
		log.Info("call_execute2", "reqId", reqId, "amountIn", amountIn, "isFront", isFront, "nextBlockNum", nextBlockNum, "data_hex", common.Bytes2Hex(data))
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
