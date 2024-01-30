package tests

import (
	"encoding/json"
	"fmt"
	"gonum.org/v1/gonum/optimize"
	"strconv"
	"testing"
	"time"
)

func TestMinimize(t *testing.T) {

	startTime := time.Now()

	balance := 5.3
	minAmountIn := 3.0

	//var bestInFunc = func(x []float64) float64 { return 0 }

	bestInFunc := func(x []float64) float64 {
		defer func() {
			if err := recover(); err != nil {
				println("err111", err)
			}
		}()
		amountInFloat := x[0]
		if amountInFloat > balance || amountInFloat < minAmountIn {
			println("尝试不在范围内的值", amountInFloat)
			return 0.0
		}
		amountOutFloat := callFunc(amountInFloat)
		if amountOutFloat > 0 {
			sprintf1 := fmt.Sprintf("%s BNBs", strconv.FormatFloat(amountInFloat, 'f', 64, 64))
			sprintf2 := fmt.Sprintf("%s BNBs", strconv.FormatFloat(amountOutFloat, 'f', 64, 64))
			println(sprintf1, sprintf2)
			return 0.0 - amountOutFloat
		}
		println("default", amountInFloat, 0)
		return 0.0
	}

	bestGrad := func(grad, x []float64) {
		defer func() {
			if err := recover(); err != nil {
				println("err222", err)
			}
		}()
		if len(x) != len(grad) {
			panic("incorrect size of the gradient")
		}

		//dim := len(x)
		for i := range grad {
			println(grad[i], x[i])
		}
		//// Prevent fused multiply add and fused multiply subtract.
		//for i := 0; i < dim-1; i++ {
		//	grad[i] -= float64(2 * (1 - x[i]))
		//	grad[i] -= float64(400 * (x[i+1] - float64(x[i]*x[i])) * x[i])
		//}
		//for i := 1; i < dim; i++ {
		//	grad[i] += float64(200 * (x[i] - float64(x[i-1]*x[i-1])))
		//}

	}

	p := optimize.Problem{
		Func: bestInFunc,
		Grad: bestGrad,
	}
	var meth = &optimize.NelderMead{} // 下山单纯形法
	//var meth = &optimize.BFGS{}
	//var meth = &optimize.CmaEsChol{} // 执行次数多
	//var meth = &optimize.GradientDescent{}
	//var meth = &optimize.LBFGS{}
	//var meth = &optimize.NelderMead{} // 这个最好用
	//var meth = &optimize.Newton{}
	//var meth = &optimize.ListSearch{}
	//var meth = &optimize.CG{}
	var p0 = []float64{3.5} // initial value for mu

	var initValues = &optimize.Location{X: p0}

	settings := &optimize.Settings{
		FuncEvaluations: 100,
		Runtime:         10 * time.Millisecond,
		Concurrent:      20,
	}

	settings.Converger = &optimize.FunctionConverge{
		Absolute:   1e32,
		Relative:   1e32,
		Iterations: 25,
	}

	res, _ := optimize.Minimize(p, initValues.X, settings, meth)
	//res, _ := optimize.Minimize(p, initValues.X, &optimize.Settings{}, meth)

	resJson, _ := json.Marshal(res)

	println(string(resJson))

	x := res.X[0]

	amountIn := fmt.Sprintf("%s BNBs", strconv.FormatFloat(x, 'f', 64, 64))

	max := callFunc(x)

	since := time.Since(startTime).Microseconds()
	println(amountIn, max, since)

}

// 调用合约的返回值
func callFunc(x float64) float64 {

	// 顶点坐标轴（2，8）
	y := -x*x + 4*x + 4

	return y
}
