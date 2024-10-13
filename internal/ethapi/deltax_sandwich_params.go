package ethapi

import (
	"github.com/ethereum/go-ethereum/common"
	"math"
	"math/big"
)

var (
	sandwichSelectorBuy  = []byte{0x00, 0x00, 0x00, 0x01}
	sandwichSelectorSale = []byte{0x00, 0x00, 0x00, 0x10}

	SandwichBigIntZeroValue = big.NewInt(0)
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
	BuyConfigNew struct {
		Simulate    bool
		ZeroForOne  bool
		IsBackRun   bool
		CheckAmount bool
		Version     int
	}

	CommonPathInfo struct {
		TokenIn     common.Address
		TokenOut    common.Address
		PairsOrPool common.Address
		Router      common.Address
		ZeroForOne  bool
		CheckTax    bool
		Version     int
		Fee         *big.Int
		AmountIn    *big.Int
		AmountOut   *big.Int
	}
)

func NewBuyConfigNew(zeroForOne bool, isBackRun bool, checkAmount bool, version int) *BuyConfigNew {

	return &BuyConfigNew{
		Simulate:    Simulate,
		ZeroForOne:  zeroForOne,
		IsBackRun:   isBackRun,
		CheckAmount: checkAmount,
		Version:     version,
	}
}

func buyConfigNewToBigInt(config *BuyConfigNew) *big.Int {

	configInt := 0
	if config.Simulate {
		configInt += lsh7
	}
	if config.ZeroForOne {
		configInt += lsh6
	}
	if config.IsBackRun {
		configInt += lsh5
	}
	if config.CheckAmount {
		configInt += lsh4
	}
	configInt += config.Version

	return big.NewInt(int64(configInt))
}

//--------------------------------------------------------------------------------

type SaleConfigNew struct {
	IsBackRun     bool
	Simulate      bool
	CalcAmountOut bool
	FeeToBuilder  bool
}

func NewSaleConfigNew(
	calcAmountOut bool,
	isBackRun bool,
	feeToBuilder bool,
) *SaleConfigNew {
	return &SaleConfigNew{
		Simulate:      Simulate,
		CalcAmountOut: calcAmountOut,
		IsBackRun:     isBackRun,
		FeeToBuilder:  feeToBuilder,
	}
}

func saleConfigNewToBigInt(config *SaleConfigNew) *big.Int {
	configInt := int64(0)
	if config.Simulate {
		configInt += lsh7
	}
	if config.CalcAmountOut {
		configInt += lsh6
	}
	if config.IsBackRun {
		configInt += lsh5
	}
	if config.FeeToBuilder {
		configInt += lsh0
	}
	return big.NewInt(configInt)
}

//-------------------------------------------------------------------

func lenAndIntSizeToBigInt(intSize, len int) *big.Int {
	result := 0
	result += intSize << 4
	result += len
	return big.NewInt(int64(result))
}

func zeroForOneVersionToBigInt(zeroForOne, checkTax bool, version int) *big.Int {

	result := 0
	if zeroForOne {
		result += lsh6
	}
	if checkTax {
		result += lsh5
	}
	result += version
	return big.NewInt(int64(result))
}

func intToBool(i int) bool {
	if i == 1 {
		return true
	} else {
		return false
	}
}

//--------------------------------------------------------------------

func SandwichEncodeParamsBuy(
	config *BuyConfigNew,
	pair common.Address,
	routerAddress common.Address,
	amountIn *big.Int,
	amountOut *big.Int,
	minTokenOutBalance *big.Int,
	tokenIn common.Address,
	builderAddress common.Address,
	bribery *big.Int,
	tokenOut common.Address,
	fee *big.Int,
) []byte {
	params := make([]byte, 0)
	params = append(params, sandwichSelectorBuy...)

	params = append(params, fillBytes(1, buyConfigNewToBigInt(config).Bytes())...)

	params = append(params, pair.Bytes()...)
	params = append(params, getShortByte(amountIn, shortNumberSize4)...)

	if config.Version == V3 {
		params = append(params, getShortByte(SandwichBigIntZeroValue, shortNumberSize4)...)
	} else {
		params = append(params, getShortByte(amountOut, shortNumberSize4)...)
	}

	if config.IsBackRun || Simulate {
		params = append(params, getShortByte(minTokenOutBalance, shortNumberSize4)...)
		params = append(params, tokenIn.Bytes()...)
		params = append(params, builderAddress.Bytes()...)
		params = append(params, getShortByte(bribery, shortNumberSize4)...)
	}

	if config.Simulate {
		params = append(params, tokenOut.Bytes()...)
		params = append(params, fillBytes(2, fee.Bytes())...)
	}

	if config.Version == Version5 && routerAddress != SandwichNullAddress {
		params = append(params, routerAddress.Bytes()...)
	}

	return params
}

func SandwichEncodeParamsSale(
	config *SaleConfigNew,
	pathInfos []*CommonPathInfo,
	amountIn *big.Int,
	minTokenOutBalance *big.Int,
	builderAddress common.Address,
	briberyWei *big.Int,
) []byte {

	var shortNumberSize int
	var intSize int

	if !config.CalcAmountOut {

		var numbers []*big.Int
		for index, pathInfo := range pathInfos {
			if index == 0 {
				if pathInfo.Version != V3 {
					numbers = append(numbers, pathInfo.AmountOut)
				}
			} else if index == 1 {
				if pathInfo.Version == V3 {
					numbers = append(numbers, pathInfo.AmountIn)
				} else {
					numbers = append(numbers, pathInfo.AmountOut)
				}
			}
		}
		for _, number := range numbers {
			i := len(number.Bytes())
			if i > intSize {
				intSize = i
			}
		}
		shortNumberSize = intSize * 8
	}

	params := make([]byte, 0)
	params = append(params, sandwichSelectorSale...)
	params = append(params, fillBytes(1, lenAndIntSizeToBigInt(intSize, len(pathInfos)).Bytes())...)
	params = append(params, fillBytes(1, saleConfigNewToBigInt(config).Bytes())...)
	params = append(params, getShortByte(amountIn, shortNumberSize4)...)
	params = append(params, getShortByte(minTokenOutBalance, shortNumberSize4)...)

	numberHeap := []byte{0x00}
	routerHeap := []byte{0x00, 0x00, 0x00}

	needRouter := false

	for index, pathInfo := range pathInfos {

		if !(!config.IsBackRun && index == 0) {
			params = append(params, pathInfo.TokenIn.Bytes()...)
		}

		params = append(params, pathInfo.PairsOrPool.Bytes()...)
		params = append(params, fillBytes(1, zeroForOneVersionToBigInt(pathInfo.ZeroForOne, pathInfo.CheckTax, pathInfo.Version).Bytes())...)

		if config.CalcAmountOut {
			params = append(params, fillBytes(2, pathInfo.Fee.Bytes())...)
		} else {
			params = append(params, []byte{0x00, 0x00}...)

			if index == 0 {
				if pathInfo.Version != V3 && pathInfo.Version != Version5 {
					getIndexAndSetNumber(intSize, shortNumberSize, pathInfo.AmountOut, &numberHeap)
				}
			} else if index == 1 {

				if pathInfo.Version == Version4 {
					getIndexAndSetNumber(intSize, shortNumberSize, pathInfo.AmountIn, &numberHeap)
					getIndexAndSetNumber(intSize, shortNumberSize, pathInfo.AmountOut, &numberHeap)
				} else {
					if pathInfo.Version == V3 || pathInfo.Version == Version5 {
						getIndexAndSetNumber(intSize, shortNumberSize, pathInfo.AmountIn, &numberHeap)
					} else {
						getIndexAndSetNumber(intSize, shortNumberSize, pathInfo.AmountOut, &numberHeap)
					}
				}
			}
		}
		//-----router---------------------
		if pathInfo.Version == Version5 {
			setRouter(index, pathInfo.Router, &routerHeap)
			needRouter = true
		}
	}

	if !config.IsBackRun {
		pathLen := len(pathInfos)
		finalToken := pathInfos[pathLen-1].TokenOut
		params = append(params, finalToken.Bytes()...)
	}

	if !config.CalcAmountOut {
		if needRouter {
			heap := numberHeap
			heap[0] = byte(len(numberHeap))
		}
		params = append(params, numberHeap...)
	}

	if needRouter {
		params = append(params, routerHeap...)
	}

	if config.FeeToBuilder {
		params = append(params, builderAddress.Bytes()...)
		params = append(params, getShortByte(briberyWei, shortNumberSize4)...)
	}

	return params
}

func setRouter(index int, router common.Address, routerHeap *[]byte) {

	heap := *routerHeap
	heap[index+1] = byte(3 + (len(*routerHeap) - 3))
	*routerHeap = append(*routerHeap, router.Bytes()...)
}

func getIndexAndSetNumber(intSize, shortNumberSize int, number *big.Int, numberHeap *[]byte) {

	var shortNumString string
	offset := 0
	number2text := number.Text(2)

	if len(number2text) > shortNumberSize {
		shortNumString = number2text[:shortNumberSize]
		if intSize == 4 {
			offset = len(number2text[shortNumberSize:])
		}
	} else {
		shortNumString = number2text
	}

	shortNumInt, _ := new(big.Int).SetString(shortNumString, 2)

	if intSize == 4 {
		offsetByte := big.NewInt(int64(offset)).Bytes()
		*numberHeap = append(*numberHeap, fillBytes(1, offsetByte)...)
		*numberHeap = append(*numberHeap, fillBytes(3, shortNumInt.Bytes())...)
	} else {
		*numberHeap = append(*numberHeap, fillBytes(intSize, shortNumInt.Bytes())...)
	}

}

func getShortByte(number *big.Int, shortNumberSize int) []byte {

	var shortNumString string
	offset := 0
	number2text := number.Text(2)

	if len(number2text) > shortNumberSize {
		shortNumString = number2text[:shortNumberSize]
		offset = len(number2text[shortNumberSize:])
	} else {
		shortNumString = number2text
	}

	offsetByte := big.NewInt(int64(offset)).Bytes()

	shortNumInt, _ := new(big.Int).SetString(shortNumString, 2)

	var result []byte

	result = append(result, fillBytes(1, offsetByte)...)
	result = append(result, fillBytes(3, shortNumInt.Bytes())...)

	return result
}

func encodeParamsSaleNew(
	amountIn1 *big.Int,
	amountOut1 *big.Int,
	amountIn2 *big.Int,
	amountOut2 *big.Int,

	pairOrPool1 common.Address,
	router1 common.Address,
	pairOrPool2 common.Address,
	router2 common.Address,

	token1 common.Address,
	token2 common.Address,
	token3 common.Address,

	option *SaleOption,
	config *SaleConfig,

	fee1 *big.Int,
	fee2 *big.Int,

	minTokenOutBalance *big.Int,
	builderAddress common.Address,
	briberyWei *big.Int,
) []byte {

	commonPathInfo1 := &CommonPathInfo{
		TokenIn:     token1,
		TokenOut:    token2,
		PairsOrPool: pairOrPool1,
		Router:      router1,
		ZeroForOne:  intToBool(option.ZeroForOne1),
		Version:     option.Version1,
		CheckTax:    Simulate,
		Fee:         fee1,
		AmountIn:    amountIn1,
		AmountOut:   amountOut1,
	}

	commonPathInfo2 := &CommonPathInfo{
		TokenIn:     token2,
		TokenOut:    token3,
		PairsOrPool: pairOrPool2,
		Router:      router2,
		ZeroForOne:  intToBool(option.ZeroForOne2),
		Version:     option.Version2,
		CheckTax:    Simulate,
		Fee:         fee2,
		AmountIn:    amountIn2,
		AmountOut:   amountOut2,
	}

	var commonPathInfos []*CommonPathInfo
	commonPathInfos = append(commonPathInfos, commonPathInfo1)
	commonPathInfos = append(commonPathInfos, commonPathInfo2)

	configNew := NewSaleConfigNew(config.CalcAmountOut, config.IsBackRun, config.FeeToBuilder)

	result := SandwichEncodeParamsSale(configNew, commonPathInfos, amountIn1, minTokenOutBalance, builderAddress, briberyWei)

	return result
}

func encodeParamsBuyNew(
	version int,
	isFront bool,
	amountIn *big.Int,
	pairOrPool common.Address,
	router common.Address,
	tokenIn common.Address,
	tokenOut common.Address,
	config *BuyConfig,
	fee *big.Int,
	amountOut *big.Int,
	minTokenOutBalance *big.Int,
	builderAddress common.Address,
	briberyWei *big.Int,
) []byte {

	isBackRun := !isFront
	configNew := NewBuyConfigNew(intToBool(config.ZeroForOne), isBackRun, config.CalcAmountOut, version)

	params := SandwichEncodeParamsBuy(configNew, pairOrPool, router, amountIn, amountOut, minTokenOutBalance, tokenIn, builderAddress, briberyWei, tokenOut, fee)

	return params
}

func GetShortNumber(number *big.Int) *big.Int {

	number2text := number.Text(2)

	if len(number2text) <= shortNumberSize4 {
		return number
	}

	shortNumString := number2text[:shortNumberSize4]

	offset := len(number2text[shortNumberSize4:])

	shortNumInt, _ := new(big.Int).SetString(shortNumString, 2)

	twoOffsetFloat := new(big.Float).SetFloat64(math.Pow(2, float64(offset)))

	twoOffsetInt := new(big.Int)

	twoOffsetFloat.Int(twoOffsetInt)

	shortNumInt.Mul(shortNumInt, twoOffsetInt)

	return shortNumInt

}
