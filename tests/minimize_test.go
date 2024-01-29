package tests

import (
	"encoding/json"
	"gonum.org/v1/gonum/optimize"
	"math/big"
	"testing"
)

func TestMinimize(t *testing.T) {

	balance := 18.0
	minAmountIn := 1.1

	var bestInFunc = func(x []float64) float64 { return 0 }

	bestInFunc = func(x []float64) float64 {
		defer func() {
			if err := recover(); err != nil {
				println("err111", err)
			}
		}()

		amountInFloat := x[0]

		if amountInFloat > balance || amountInFloat < minAmountIn {
			return 0.0
		}

		amountOutFloat := callFunc(amountInFloat)

		if amountOutFloat > 0 {
			println(amountInFloat, amountOutFloat)
			return 0.0 - amountOutFloat
		}

		println(amountInFloat, 0)
		return 0.0
	}

	p := optimize.Problem{
		Func: bestInFunc,
	}

	var meth = &optimize.NelderMead{} // 下山单纯形法
	//var meth = &optimize.CmaEsChol{}
	var p0 = []float64{1} // initial value for mu : 1e18

	var initValues = &optimize.Location{X: p0}

	res, _ := optimize.Minimize(p, initValues.X, &optimize.Settings{}, meth)

	resJson, _ := json.Marshal(res)

	println(string(resJson))

	x := res.X[0]

	max := callFunc(x)

	println(max)

}

// 调用合约的返回值
func callFunc(x float64) float64 {

	defer func() *big.Float {
		if err := recover(); err != nil {
			println("err", err)
		}
		return big.NewFloat(0)
	}()

	result := make(map[float64]float64)

	result[1.1] = 1.01
	result[1.2] = 1.02
	result[1.3] = 1.03
	result[1.4] = 1.04
	result[1.5] = 1.05
	result[1.55] = 1.055
	result[1.555] = 1.0555
	result[1.5555] = 1.05555
	result[1.55555] = 1.055555
	result[1.6] = 0
	result[1.7] = 0

	float := result[x]

	return float
}
