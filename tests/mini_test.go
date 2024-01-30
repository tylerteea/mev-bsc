package tests

import (
	"encoding/json"
	"fmt"
	"gonum.org/v1/gonum/optimize"
	"gonum.org/v1/gonum/optimize/functions"
	"log"
	"testing"
)

func TestMini(t *testing.T) {

	p := optimize.Problem{
		Func: functions.ExtendedRosenbrock{}.Func,
		//Grad: functions.ExtendedRosenbrock{}.Grad,
	}

	x := []float64{1.3, 0.7, 0.8, 1.9, 1.2}
	result, err := optimize.Minimize(p, x, nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	if err = result.Status.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("result.Status: %v\n", result.Status)
	fmt.Printf("result.X: %0.4g\n", result.X)
	fmt.Printf("result.F: %0.4g\n", result.F)
	fmt.Printf("result.Stats.FuncEvaluations: %d\n", result.Stats.FuncEvaluations)

	resJson, _ := json.Marshal(result)

	println(string(resJson))
	// Output:
	// result.Status: GradientThreshold
	// result.X: [1 1 1 1 1]
	// result.F: 4.98e-30
	// result.Stats.FuncEvaluations: 31
}
