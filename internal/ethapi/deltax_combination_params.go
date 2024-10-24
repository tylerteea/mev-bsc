package ethapi

import (
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

var (
	Sandwich     = big.NewInt(0)
	Cycle        = big.NewInt(1)
	DirectionAdd = big.NewInt(0)
	DirectionSub = big.NewInt(1)

	SandwichBigIntZeroValue = big.NewInt(0)
	SandwichBigIntOneValue  = big.NewInt(1)
	SandwichNullAddress     = common.HexToAddress("0x0000000000000000000000000000000000000000")
)

const (
	lsh7 = 1 << 7
	lsh6 = 1 << 6
	lsh5 = 1 << 5
	lsh4 = 1 << 4

	lsh0 = 1 << 0

	IntSize4         = 4
	shortNumberSize4 = (IntSize4 - 1) * 8

	Version5 = 5
	Version4 = 4
)

//-------------------------------------------------------------------

type (
	CommonPathInfo struct {
		TokenIn     common.Address `json:"tokenIn"`
		TokenOut    common.Address `json:"tokenOut"`
		PairsOrPool common.Address `json:"pairsOrPool"`
		Router      common.Address `json:"router"`
		ZeroForOne  bool           `json:"zeroForOne"`
		Version     int            `json:"version"`
		Fee         *big.Int       `json:"fee"`
	}

	ParamHead struct {
		Builder        *big.Int
		Strategy       *big.Int
		CountSeqBigInt *big.Int
		GlobalConfig   *big.Int
		BundleId       *big.Int
		Bribery        *big.Int
	}
)

func NewParamHead(
	builder *big.Int,
	strategy *big.Int,
	countSeqBigInt *big.Int,
	globalConfig *big.Int,
	bundleId *big.Int,
	bribery *big.Int,
) *ParamHead {
	return &ParamHead{
		Builder:        builder,
		Strategy:       strategy,
		CountSeqBigInt: countSeqBigInt,
		GlobalConfig:   globalConfig,
		BundleId:       bundleId,
		Bribery:        bribery,
	}
}

//-------------------------------------------------------------------------------------------------balanceCheck

type BalanceCheck struct {
	Token      common.Address
	Direction  *big.Int
	AmountDiff *big.Int
}

func NewBalanceCheck(token common.Address, direction *big.Int, amountDiff *big.Int) *BalanceCheck {
	return &BalanceCheck{
		Token:      token,
		Direction:  direction,
		AmountDiff: amountDiff,
	}
}

//-------------------------------------------------------------------------------------------------router

type Router struct {
	RouterType *big.Int
	SwapCount  *big.Int
	Swaps      []*Swap
}

func NewRouter(routerType *big.Int, swapCount *big.Int, swaps []*Swap) *Router {
	return &Router{
		RouterType: routerType,
		SwapCount:  swapCount,
		Swaps:      swaps,
	}
}

type Swap struct {
	TokenIn    common.Address
	PairOrPool common.Address
	ZeroForOne bool
	Version    int
	AmountIn   *big.Int
	AmountOut  *big.Int
	Fee        *big.Int
	TokenOut   common.Address
}

func NewSwap(tokenIn common.Address, pairOrPool common.Address, zeroForOne bool, version int, amountIn *big.Int, amountOut *big.Int, fee *big.Int, tokenOut common.Address) *Swap {
	return &Swap{
		TokenIn:    tokenIn,
		PairOrPool: pairOrPool,
		ZeroForOne: zeroForOne,
		Version:    version,
		AmountIn:   amountIn,
		AmountOut:  amountOut,
		Fee:        fee,
		TokenOut:   tokenOut,
	}
}

// -------------------------------------------------------------------------------------------------
func zeroForOneAndVersionToBigInt(zeroForOne bool, version int) *big.Int {
	result := 0
	if zeroForOne {
		result += lsh6
	}
	result += version
	return big.NewInt(int64(result))
}

func globalConfigToBigInt(globalConfig bool) *big.Int {
	if globalConfig {
		return SandwichBigIntOneValue
	} else {
		return SandwichBigIntZeroValue
	}
}

func getHead(tradeType int, briberyWei *big.Int) (*ParamHead, *ParamHead) {
	globalConfig := globalConfigToBigInt(Simulate)
	strategy := SandwichBigIntZeroValue
	countSeq := SandwichBigIntZeroValue
	bundleId := SandwichBigIntZeroValue

	frontBuilder := SandwichBigIntZeroValue
	frontBribery := SandwichBigIntZeroValue
	frontParamHead := NewParamHead(frontBuilder, strategy, countSeq, globalConfig, bundleId, frontBribery)

	backBuilder := big.NewInt(int64(tradeType))
	backBribery := briberyWei
	backParamHead := NewParamHead(backBuilder, strategy, countSeq, globalConfig, bundleId, backBribery)

	return frontParamHead, backParamHead
}

func MakeParams(paramHead *ParamHead, balanceChecks []*BalanceCheck, routers []*Router) []byte {

	params := make([]byte, 0)

	//-------------------------------------------------------------------------------------------------head
	params = append(params, FillBytes(1, paramHead.Builder.Bytes())...)
	params = append(params, FillBytes(1, paramHead.Strategy.Bytes())...)
	params = append(params, FillBytes(1, paramHead.CountSeqBigInt.Bytes())...)
	params = append(params, FillBytes(1, paramHead.GlobalConfig.Bytes())...)
	params = append(params, FillBytes(4, paramHead.BundleId.Bytes())...)
	params = append(params, FillBytes(10, paramHead.Bribery.Bytes())...)

	//-------------------------------------------------------------------------------------------------balanceCheck
	balanceDiffCount := big.NewInt(int64(len(balanceChecks)))
	params = append(params, FillBytes(1, balanceDiffCount.Bytes())...)

	for _, check := range balanceChecks {
		params = append(params, FillBytes(20, check.Token.Bytes())...)
		params = append(params, FillBytes(1, check.Direction.Bytes())...)
		params = append(params, FillBytes(14, check.AmountDiff.Bytes())...)
	}

	//-------------------------------------------------------------------------------------------------router
	routerCount := big.NewInt(int64(len(routers)))
	params = append(params, FillBytes(1, routerCount.Bytes())...)

	for _, router := range routers {

		swapParams := make([]byte, 0)
		for index, swap := range router.Swaps {

			swapParams = append(swapParams, FillBytes(20, swap.TokenIn.Bytes())...)
			swapParams = append(swapParams, FillBytes(20, swap.PairOrPool.Bytes())...)

			swapConfig := zeroForOneAndVersionToBigInt(swap.ZeroForOne, swap.Version)
			swapParams = append(swapParams, FillBytes(1, swapConfig.Bytes())...)

			swapParams = append(swapParams, FillBytes(14, swap.AmountIn.Bytes())...)

			if Simulate {
				swapParams = append(swapParams, FillBytes(14, swap.Fee.Bytes())...)
			} else {
				swapParams = append(swapParams, FillBytes(14, swap.AmountOut.Bytes())...)
			}

			if index == len(router.Swaps)-1 {
				if Simulate {
					swapParams = append(swapParams, FillBytes(20, swap.TokenOut.Bytes())...)
				} else {
					if swap.Version == Version5 {
						swapParams = append(swapParams, FillBytes(20, swap.TokenOut.Bytes())...)
					}
				}
			}
		}

		params = append(params, FillBytes(1, router.RouterType.Bytes())...)

		dataLen := big.NewInt(int64(len(swapParams) + 4))
		params = append(params, FillBytes(2, dataLen.Bytes())...)

		params = append(params, FillBytes(1, router.SwapCount.Bytes())...)
		params = append(params, swapParams...)
	}
	return params
}
