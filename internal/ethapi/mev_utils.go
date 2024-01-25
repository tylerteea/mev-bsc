package ethapi

import (
	"github.com/ethereum/go-ethereum/log"
	"time"
)

func timeCost(reqId string, start time.Time) {
	tc := time.Since(start)
	log.Info("call_cost", "reqId", reqId, "ms", tc.Milliseconds())
}

//
//// a = 初始最小输入， b = 账户余额 即最大输入   正常情况下 a < b
//func getMax(args *CallArgs, a, b, stepAmount, steps *big.Int) (int, *big.Int, *big.Int, error) {
//
//	log.Info("call_sbp_getMax_start", "reqId", args.reqId, "左边界", a, "右边界", b, "步长", stepAmount)
//
//	totalCount, tmpX, tmpY, isConcave, err := concave(args, a, b, stepAmount, steps)
//
//	log.Info("call_sbp_getMax_concave", "reqId", args.reqId, "totalCount", totalCount, "tmpX", tmpX, "tmpY", tmpY, "isConcave", isConcave, "err", err)
//
//	if err != nil {
//		// 如果连凹凸函数都判断不出来，则直接返回失败
//		if isConcave {
//			// 代表走降级流程，默认是凹函数,返回当前已经获取过的某个x值对应的y值
//			return totalCount, tmpX, tmpY, nil
//		}
//		return totalCount, nil, nil, err
//	}
//	// 如果是凹函数，则最大值为左右边界中较大的一个
//	if isConcave {
//		exeTotalCount, x, y, errMaxSearchOfConcave := maxSearchOfConcave(args, a, b, stepAmount)
//		totalCount += exeTotalCount
//		log.Info("call_sbp_getMax_execute_concave", "reqId", args.reqId, "totalCount", totalCount, "tmpX", x, "tmpY", y, "err", errMaxSearchOfConcave)
//		return totalCount, x, y, errMaxSearchOfConcave
//	} else {
//		// 如果是凸函数，开始走近似二分查找
//		log.Info("call_sbp_getMax_execute_maxSearch", "reqId", args.reqId)
//		exeTotalCount, x, y, errMaxSearch := maxSearch(args, a, b, stepAmount)
//		totalCount += exeTotalCount
//		log.Info("call_sbp_getMax_end", "reqId", args.reqId, "maxX", x, "maxY", y, "maxX", "err", err)
//		return totalCount, x, y, errMaxSearch
//	}
//}
//
//func callResultFuncForCount(args *CallArgs, x, step *big.Int, count int, addOrSub bool) (int, *big.Int, *big.Int, error) {
//
//	var y *big.Int
//	executeCount := 0
//	var err error
//
//	for i := 0; i < count; i++ {
//		y, err = callResultFunc(args, x)
//		executeCount++
//		if err != nil {
//			if addOrSub {
//				x = new(big.Int).Add(x, step)
//			} else {
//				x = new(big.Int).Sub(x, step)
//			}
//			continue
//		} else {
//			return executeCount, x, y, nil
//		}
//	}
//	if err == nil {
//		err = errors.New("call_err")
//	}
//	return executeCount, x, nil, err
//}
//
//// 默认情况下 a < b
//func maxSearchOfConcave(args *CallArgs, a, b, step *big.Int) (int, *big.Int, *big.Int, error) {
//
//	totalCount := 0
//
//	// a 向右收缩 ，尝试3次
//	exeCountA, tmpA, aValue, aErr := callResultFuncForCount(args, a, step, 3, true)
//	totalCount += exeCountA
//	log.Info("call_sbp_getMax_2_1", "reqId", args.reqId, "err", aErr, "a", tmpA, "aValue", aValue)
//	if aErr == nil {
//		// 修改初始值为 能够正常调用合约的最小值
//		a = tmpA
//	}
//
//	// b 向左收缩，尝试3次
//	exeCountB, tmpB, bValue, bErr := callResultFuncForCount(args, b, step, 3, false)
//	totalCount += exeCountB
//	log.Info("call_sbp_getMax_2_2", "reqId", args.reqId, "err", bErr, "b", tmpB, "bValue", bValue)
//	if bErr == nil { // 如果重试三次仍找不到，就停止寻找
//		b = tmpB
//	}
//
//	// 全为空
//	if aValue == nil && bValue == nil {
//		log.Info("call_sbp_getMax_2_3", "reqId", args.reqId, "边界值f(a)f(b)均为空", "")
//		return totalCount, nil, nil, errors.New("边界值f(a)f(b)均为空")
//	}
//	// 全不为空
//	if aValue != nil && bValue != nil {
//		log.Info("call_sbp_getMax_2_4", "reqId", args.reqId, "边界值f(a)", aValue, "f(b)", bValue)
//		if aValue.Int64() > bValue.Int64() {
//			return totalCount, a, aValue, nil
//		} else {
//			return totalCount, b, bValue, nil
//		}
//	}
//	// 降级方案：谁不空，返回谁
//	log.Info("call_sbp_getMax_2_5", "reqId", args.reqId, "边界值有一个为空，f(a)", aValue, "f(b)", bValue)
//	if aValue != nil {
//		return totalCount, a, aValue, nil
//	}
//	if bValue != nil {
//		return totalCount, b, bValue, nil
//	}
//	return totalCount, nil, nil, errors.New("unknown")
//}
//
//// 二分查找近似最大值
//func maxSearch(args *CallArgs, left, right, stepAmount *big.Int) (int, *big.Int, *big.Int, error) {
//
//	log.Info("call_sbp_maxSearch_start", "reqId", args.reqId)
//
//	maxValue := big.NewInt(0)
//	count := 0
//	tryCount := 2
//
//	for left.Int64() < right.Int64() {
//
//		log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "count", count)
//		middle := mean(left, right)
//
//		// 中间值
//		midCount, midx, midY, yErr := callResultFuncForCount(args, middle, stepAmount, tryCount, false)
//		count += midCount
//		if yErr != nil {
//			log.Info("callResultFunc error midY is nil : ", middle)
//			right = new(big.Int).Sub(middle, stepAmount)
//			continue
//		} else {
//			middle = midx
//		}
//
//		middleSub1 := new(big.Int).Sub(middle, stepAmount)
//		//中间值 - 1步
//		midSubCount, midSubX, midSubY, subErr := callResultFuncForCount(args, middleSub1, stepAmount, tryCount, false)
//		count += midSubCount
//		if subErr != nil {
//			log.Info("callResultFunc error midSub is nil : ", middleSub1)
//			continue
//		} else {
//			middleSub1 = midSubX
//		}
//
//		middleAdd1 := new(big.Int).Add(middle, stepAmount)
//		//中间值 + 1步
//		midAddCount, midAddX, midAddY, addErr := callResultFuncForCount(args, middleAdd1, stepAmount, tryCount, true)
//		count += midAddCount
//		if addErr != nil {
//			log.Info("callResultFunc error midAdd is nil : ", middleAdd1)
//			continue
//		} else {
//			middleAdd1 = midAddX
//		}
//
//		// 如果f(x)大于左右两侧的f(x-1)和f(x+1)，那么认为此时x可以获得最大值y
//		if midY.Int64() > midSubY.Int64() && midY.Int64() > midAddY.Int64() {
//			log.Info("find_max_x_y_1 : ", left, maxValue)
//			log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "totalCount", count, "x", left, "y", maxValue)
//			return count, middle, midY, nil
//		} else if midY.Int64() > midSubY.Int64() {
//			log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "count", count, "右侧有更大值， 左侧的边界向中间移动left", left, "maxValue", maxValue)
//			left = middleAdd1 // 右侧有更大值， 左侧的边界向中间移动
//		} else {
//			log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "count", count, "左侧有更大值 ,右侧的边界向中间移动right", right, "maxValue", maxValue)
//			right = middleSub1 // 左侧有更大值 ,右侧的边界向中间移动
//		}
//	}
//
//	log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "totalCount", count, "x", left, "y", maxValue)
//	return count, left, maxValue, nil
//}
//
//// 2数求平均
//func mean(a, b *big.Int) *big.Int {
//	sum := new(big.Int).Add(a, b)
//	return new(big.Int).Div(sum, big.NewInt(2))
//}
//
//// 是否是凹函数
//func concave(args *CallArgs, a, b, stepAmount, steps *big.Int) (int, *big.Int, *big.Int, bool, error) {
//
//	totalCount := 0
//
//	exeCountA, tmpA, funA, aErr := callResultFuncForCount(args, a, stepAmount, 3, true)
//	totalCount += exeCountA
//	if aErr == nil && tmpA != nil && funA != nil {
//		// 如果初始值不可用，就向右移动寻找可用值，并修改初始值
//		a = tmpA
//	} else {
//		// 如果找不到，降级到，是凹函数
//		return totalCount, nil, nil, true, aErr
//	}
//
//	exeCountB, tmpB, funB, bErr := callResultFuncForCount(args, b, stepAmount, 3, false)
//	totalCount += exeCountB
//	if bErr == nil && tmpB != nil && funB != nil {
//		// 如果初始值不可用，就向右移动寻找可用值，并修改
//		b = tmpB
//	} else {
//		// 如果找不到，降级到，是凹函数
//		return totalCount, nil, nil, true, bErr
//	}
//
//	middle := mean(a, b)
//	exeCountMid, _, middleFunc, err := callResultFuncForCount(args, middle, stepAmount, 3, false)
//	totalCount += exeCountMid
//	if err != nil { // 如果中间值找不到，降级到，是凹函数
//		if funA.Int64() >= funB.Int64() {
//			return totalCount, a, funA, true, err
//		} else {
//			return totalCount, b, funB, true, err
//		}
//	}
//
//	middleDiv2 := mean(funA, funB)
//	return totalCount, a, b, middleDiv2.Int64() > middleFunc.Int64(), nil
//}
//
//// 调用合约的返回值
//func callResultFunc(args *CallArgs, amountInReal *big.Int) (*big.Int, error) {
//
//	result, err := realCall(args.ctx, args.head, args.s, args.sbp, args.reqId, args.sbp.AmountOutMin, args.sdb, args.victimTxMsg, args.victimTxContext, amountInReal, args.globalGasCap)
//
//	log.Info("realCall result : ", args, amountInReal, result, err)
//
//	var amountOutReal *big.Int
//	if err == nil {
//		amountOut := result["amountOut"]
//		if amountOut != nil {
//			amountOutReal = result["amountOut"].(*big.Int)
//
//			profit := new(big.Int).Sub(amountOutReal, amountInReal)
//			log.Info("call_sbp_realCall_profit", "reqId", args.reqId, "amountIn", amountInReal, "amountOut", amountOutReal, "profit", profit)
//			if profit.Uint64() < 0 {
//				log.Info("call_sbp_realCall_profit_too_low", "reqId", args.reqId)
//			}
//			return profit, nil
//		}
//	}
//	return nil, err
//}
