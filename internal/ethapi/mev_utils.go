package ethapi

import (
	"errors"
	"github.com/ethereum/go-ethereum/log"
	"math/big"
)

// a = 初始最小输入， b = 账户余额 即最大输入   正常情况下 a < b
func getMax(args *CallArgs, a, b, stepAmount, steps *big.Int) (*big.Int, *big.Int, error) {

	log.Info("call_sbp_getMax_start", "reqId", args.reqId, "左边界", a, "右边界", b, "步长", stepAmount)

	isConcave, err := concave(args, a, b, stepAmount, steps)

	log.Info("call_sbp_getMax_1", "reqId", args.reqId, "err", err, "isConcave", isConcave)

	if err != nil {
		// 如果连凹凸函数都判断不出来，则直接返回失败
		return nil, nil, err
	}
	// 如果是凹函数，则最大值为左右边界中较大的一个
	if isConcave {
		x, y, errMaxSearchOfConcave := maxSearchOfConcave(args, a, b, stepAmount)
		return x, y, errMaxSearchOfConcave
	} else {
		// 如果是凸函数，开始走近似二分查找
		log.Info("call_sbp_getMax_3", "reqId", args.reqId, "二分查找", "maxSearch")
		x, y, errMaxSearch := maxSearch(args, a, b, stepAmount)
		log.Info("call_sbp_getMax_end", "reqId", args.reqId, "maxX", x, "maxY", y, "maxX", "err", err)
		return x, y, errMaxSearch
	}
}

func callResultFuncForCount(args *CallArgs, x, step *big.Int, count int, addOrSub bool) (*big.Int, *big.Int, error) {

	var y *big.Int
	var err error

	for i := 0; i < count; i++ {
		y, err = callResultFunc(args, x)
		if err != nil {
			if addOrSub {
				x = new(big.Int).Add(x, step)
			} else {
				x = new(big.Int).Sub(x, step)
			}
			continue
		} else {
			return x, y, nil
		}
	}
	if err == nil {
		err = errors.New("call_err")
	}
	return x, nil, err
}

func maxSearchOfConcave(args *CallArgs, a, b, step *big.Int) (*big.Int, *big.Int, error) {
	// 默认情况下 a < b

	tmpA, aValue, aErr := callResultFuncForCount(args, a, step, 3, true)

	if aErr != nil {
		return nil, nil, aErr
	} else {
		// 修改初始值为 能够正常调用合约的最小值
		a = tmpA
	}

	if aErr != nil {
		log.Info("call_sbp_getMax_2_1", "reqId", args.reqId, "err", aErr)
		return nil, nil, aErr
	}
	bValue, bErr := callResultFunc(args, b)
	if bErr != nil {
		log.Info("call_sbp_getMax_2_2", "reqId", args.reqId, "err", bErr)
		return nil, nil, bErr
	}

	// 全为空
	if aValue == nil && bValue == nil {
		log.Info("call_sbp_getMax_2_3", "reqId", args.reqId, "边界值f(a)f(b)均为空", "")
		return nil, nil, errors.New("边界值f(a)f(b)均为空")
	}
	// 全不为空
	if aValue != nil && bValue != nil {
		log.Info("call_sbp_getMax_2_4", "reqId", args.reqId, "边界值f(a)", aValue, "f(b)", bValue)
		if aValue.Int64() > bValue.Int64() {
			return a, aValue, nil
		} else {
			return b, bValue, nil
		}
	}
	// 降级方案：谁不空，返回谁
	log.Info("call_sbp_getMax_2_5", "reqId", args.reqId, "边界值有一个为空，f(a)", aValue, "f(b)", bValue)
	if aValue != nil {
		return a, aValue, nil
	}
	if bValue != nil {
		return b, bValue, nil
	}

	return nil, nil, errors.New("unknown")
}

// 二分查找近似最大值
func maxSearch(args *CallArgs, left, right, step *big.Int) (*big.Int, *big.Int, error) {

	log.Info("call_sbp_maxSearch_start", "reqId", args.reqId)

	maxValue := big.NewInt(0)
	count := 0

	for left.Int64() < right.Int64() {

		count++
		log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "count", count)
		middle := mean(left, right)

		// 中间值
		midY, yErr := callResultFunc(args, middle)
		if yErr != nil {
			log.Info("callResultFunc error midY is nil : ", middle)
			continue
		}

		middleSub1 := new(big.Int).Sub(middle, step)
		middleAdd1 := new(big.Int).Add(middle, step)
		//中间值 - 1步
		midSub, subErr := callResultFunc(args, middleSub1)
		if subErr != nil {
			log.Info("callResultFunc error midSub is nil : ", middleSub1)
			continue
		}
		//中间值 + 1步
		midAdd, addErr := callResultFunc(args, middleAdd1)
		if addErr != nil {
			log.Info("callResultFunc error midAdd is nil : ", middleAdd1)
			continue
		}

		// 如果f(x)大于左右两侧的f(x-1)和f(x+1)，那么认为此时x可以获得最大值y
		if (midY.Int64() > midSub.Int64()) && midY.Int64() > midAdd.Int64() {
			log.Info("find_max_x_y_1 : ", left, maxValue)
			log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "totalCount", count, "x", left, "y", maxValue)
			return middle, midY, nil
		} else if midY.Int64() > midSub.Int64() {
			log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "count", count, "右侧有更大值， 左侧的边界向中间移动left", left, "maxValue", maxValue)
			left = middleAdd1 // 右侧有更大值， 左侧的边界向中间移动
			maxValue = midAdd //todo
		} else {
			log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "count", count, "左侧有更大值 ,右侧的边界向中间移动right", right, "maxValue", maxValue)
			right = middleSub1 // 左侧有更大值 ,右侧的边界向中间移动
		}
	}

	log.Info("call_sbp_maxSearch_find", "reqId", args.reqId, "totalCount", count, "x", left, "y", maxValue)
	return left, maxValue, nil
}

// 2数求平均
func mean(a, b *big.Int) *big.Int {
	sum := new(big.Int).Add(a, b)
	return new(big.Int).Div(sum, big.NewInt(2))
}

// 是否是凹函数
func concave(args *CallArgs, a, b, stepAmount, steps *big.Int) (bool, error) {

	funA, aErr := callResultFunc(args, a)
	if funA == nil || aErr != nil {
		//尝试 a右移动一步
		a = new(big.Int).Add(a, stepAmount)
		funA, aErr = callResultFunc(args, a)
		// 如果仍找不到合适的值，则直接返回错误
		if aErr != nil {
			return false, aErr
		}
	}

	middle := mean(a, b)

	funB, bErr := callResultFunc(args, b)
	if funB == nil || bErr != nil {
		//尝试 b左移动到中间位置
		funB, bErr = callResultFunc(args, middle)
		// 如果仍找不到合适的值，则直接返回错误
		if bErr != nil {
			return false, bErr
		}
		// 调整中间值
		middle = mean(a, middle)
	}

	middleFunc, err := callResultFunc(args, middle)
	if err != nil {
		return false, err
	}

	middleDiv2 := mean(funA, funB)
	return middleDiv2.Int64() > middleFunc.Int64(), nil
}

// 调用合约的返回值
func callResultFunc(args *CallArgs, amountInReal *big.Int) (*big.Int, error) {

	result, err := realCall(args.ctx, args.head, args.s, args.sbp, args.reqId, args.sbp.AmountOutMin, args.sdb, args.victimTxMsg, args.victimTxContext, amountInReal, args.globalGasCap)

	log.Info("realCall result : ", args, amountInReal, result, err)

	var amountOutReal *big.Int
	if err == nil {
		amountOut := result["amountOut"]
		if amountOut != nil {
			amountOutReal = result["amountOut"].(*big.Int)
			log.Info("amountInReal、amountOutReal : ", amountInReal, amountOutReal)
			return amountOutReal, nil
		}
	}
	return nil, err
}
