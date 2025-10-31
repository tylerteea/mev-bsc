package ethapi

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi/override"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/log"
)

var (
	UniswapV4StateView     = common.HexToAddress("0xd13Dd3D6E93f276FAfc9Db9E6BB47C1180aeE0c4")
	PancakeV4CLPoolManager = common.HexToAddress("0xa0FfB9c1CE1Fe56963B0321B32E7A0302114058b")
)

type (
	CallBundleCheckAndPoolPairStateArgs struct {
		ReqId                  string                  `json:"reqId"`
		Txs                    []hexutil.Bytes         `json:"txs"`
		BlockNumber            rpc.BlockNumber         `json:"blockNumber"`
		StateBlockNumberOrHash rpc.BlockNumberOrHash   `json:"stateBlockNumber"`
		Coinbase               *string                 `json:"coinbase"`
		Timestamp              *uint64                 `json:"timestamp"`
		Timeout                *int64                  `json:"timeout"`
		GasLimit               *uint64                 `json:"gasLimit"`
		Difficulty             *big.Int                `json:"difficulty"`
		SimulationLogs         bool                    `json:"simulationLogs"`
		StateOverrides         *override.StateOverride `json:"stateOverrides"`
		BaseFee                *big.Int                `json:"baseFee"`

		NeedAccessList []bool `json:"needAccessList"`

		//pair/pool state
		Pairs []*PairInfo `json:"pairs,omitempty"`
		Pools []*PoolInfo `json:"pools,omitempty"`

		//balance
		MevContract        common.Address   `json:"mevContract,omitempty"`
		MevTokens          []common.Address `json:"mevTokens,omitempty"`
		BalanceBeforeIndex int              `json:"balanceBeforeIndex,omitempty"`
		BalanceAfterIndex  int              `json:"balanceAfterIndex,omitempty"`
	}

	PoolInfo struct {
		Address string `json:"address"`
		Version int    `json:"version"`
	}

	PairInfo struct {
		Address string `json:"address"`
		Version int    `json:"version"`
	}

	CallBundleResultNew struct {
		ErrMsg             string                     `json:"errMsg"`
		BundleGasPrice     string                     `json:"bundleGasPrice"`
		BundleHash         string                     `json:"bundleHash"`
		CheckResults       []*CheckBalanceResult      `json:"checkResults"`
		CallTracerJsResult []*CallTracerJsResult      `json:"callTracerJsResult"`
		Results            []*SimulateBundleResultNew `json:"results"`
	}

	CheckBalanceResult struct {
		BalanceType string         `json:"balanceType"`
		Token       common.Address `json:"token"`
		Balance     *big.Int       `json:"balance"`
	}

	SimulateBundleResultNew struct {
		GasUsed           uint64            `json:"gasUsed"`
		TxHash            string            `json:"txHash"`
		Value             string            `json:"value"`
		Error             string            `json:"error"`
		Revert            string            `json:"revert"`
		Logs              []*types.Log      `json:"logs"`
		AccessListGasUsed uint64            `json:"accessListGasUsed"`
		AccessListResult  *types.AccessList `json:"accessListResult"`
	}

	CallTracerJsResult struct {
		Address      string `json:"address"`
		Topic        string `json:"topic"`
		Reserve0     string `json:"reserve0"`
		Reserve1     string `json:"reserve1"`
		Amount0      string `json:"amount0"`
		Amount1      string `json:"amount1"`
		SqrtPriceX96 string `json:"sqrtPriceX96"`
		Liquidity    string `json:"liquidity"`
		Tick         string `json:"tick"`
		Type         string `json:"type"`
		Amount0In    string `json:"amount0In"`
		Amount1In    string `json:"amount1In"`
		Amount0Out   string `json:"amount0Out"`
		Amount1Out   string `json:"amount1Out"`
	}
)

func (s *BundleAPI) CallBundleCheckAndPoolPairState(ctx context.Context, args CallBundleCheckAndPoolPairStateArgs) (*CallBundleResultNew, error) {

	reqId := args.ReqId

	defer func(start time.Time) {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...CallBundleCheckBalance", "err", r, "stack", dss, "reqId", reqId)
		}

		//log.Info("CallBundleCheckBalance_end_defer", "reqId", reqId, "runtime", time.Since(start))
	}(time.Now())

	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	var txs types.Transactions
	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			log.Info("CallBundleCheckBalance_1", "reqId", reqId, "err", err)
			return nil, err
		}
		txs = append(txs, tx)
	}

	timeoutMilliSeconds := int64(2000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)
	stateHead, parent, err1 := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if stateHead == nil || err1 != nil {
		return nil, err1
	}
	// 避免相互影响
	state := stateHead.Copy()

	precompiles := map[common.Address]vm.PrecompiledContract{}
	if err2 := args.StateOverrides.Apply(state, precompiles); err2 != nil {
		return nil, err2
	}
	blockNumber := big.NewInt(int64(args.BlockNumber))

	timestamp := parent.Time + 1
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = common.HexToAddress(*args.Coinbase)
	}
	difficulty := parent.Difficulty
	if args.Difficulty != nil {
		difficulty = args.Difficulty
	}
	gasLimit := parent.GasLimit
	if args.GasLimit != nil {
		gasLimit = *args.GasLimit
	}

	var baseFee *big.Int
	if args.BaseFee != nil {
		baseFee = args.BaseFee
	} else if s.b.ChainConfig().IsLondon(big.NewInt(args.BlockNumber.Int64())) {
		baseFee = eip1559.CalcBaseFee(s.b.ChainConfig(), parent)
	}

	header := &types.Header{
		ParentHash:    parent.Hash(),
		Number:        blockNumber,
		GasLimit:      gasLimit,
		Time:          timestamp,
		Difficulty:    difficulty,
		Coinbase:      coinbase,
		BaseFee:       baseFee,
		ExcessBlobGas: parent.ExcessBlobGas,
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	vmconfig := vm.Config{NoBaseFee: true}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	var results []*SimulateBundleResultNew

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), blockNumber, header.Time)

	isPostMerge := header.Difficulty.Cmp(common.Big0) == 0
	rules := s.b.ChainConfig().Rules(header.Number, isPostMerge, header.Time)

	var CheckBalanceResults []*CheckBalanceResult

	for index, tx := range txs {

		// Check if the context was cancelled (eg. timed-out)
		if err13 := ctx.Err(); err13 != nil {
			log.Info("CallBundleCheckBalance_8", "reqId", reqId, "err", err13)
			return nil, err13
		}
		//-------------------------------------------before
		if args.MevTokens != nil {
			if args.BalanceBeforeIndex == index {
				balancesBefore, err11 := getTokenBalanceByContract(ctx, s, args.MevTokens, args.MevContract, state, header)
				if err11 != nil {
					log.Info("call_bundle_balance_err1", "reqId", reqId, "err", err11)
					return nil, err11
				}
				if len(args.MevTokens) != len(balancesBefore) {
					log.Info("call_bundle_balance_err2", "reqId", reqId, "mevTokens_len", len(args.MevTokens), "balances_len", len(balancesBefore))
					return nil, errors.New("call_bundle_balance_err2")
				}
				for i, mevTokenTmp := range args.MevTokens {

					var balancesBeforeTmp *big.Int
					if mevTokenTmp.Cmp(WbnbAddress) == 0 {
						// balancesBeforeTmp = new(big.Int).Add(balancesBefore[i], state.GetBalance(args.MevContract).ToBig())
						balancesBeforeTmp = balancesBefore[i]
						log.Info("call_bundle_balance_before", "reqId", reqId, "mevTokenTmp", mevTokenTmp, "balancesBeforeTmp", balancesBeforeTmp, "bnbBalance", state.GetBalance(args.MevContract).ToBig())
					} else {
						balancesBeforeTmp = balancesBefore[i]
					}

					checkBalanceResult := &CheckBalanceResult{
						BalanceType: "balancesBefore",
						Token:       mevTokenTmp,
						Balance:     balancesBeforeTmp,
					}
					CheckBalanceResults = append(CheckBalanceResults, checkBalanceResult)
				}
			}
		}
		//-------------------------------------------before

		from, _ := types.Sender(signer, tx)

		simulateBundleResultNew := &SimulateBundleResultNew{
			TxHash: tx.Hash().String(),
		}

		//--------access list

		if args.NeedAccessList != nil {
			need := args.NeedAccessList[index]
			if need {

				data := hexutil.Bytes(tx.Data())
				gas := hexutil.Uint64(tx.Gas())
				nonce := hexutil.Uint64(tx.Nonce())

				callArgs := TransactionArgs{
					From:     &from,
					To:       tx.To(),
					Data:     &data,
					Gas:      &gas,
					GasPrice: (*hexutil.Big)(tx.GasPrice()),
					Nonce:    &nonce,
					Value:    (*hexutil.Big)(tx.Value()),
				}

				accessList, errAL := createAccessListNew(ctx, s.b, callArgs, &args.StateBlockNumberOrHash, args.StateOverrides, state, header)

				if errAL == nil && accessList != nil {

					accessListGasUsed := uint64(accessList.GasUsed)

					simulateBundleResultNew.AccessListGasUsed = accessListGasUsed
					simulateBundleResultNew.AccessListResult = accessList.Accesslist

				} else {
					log.Info("call_bundle_createAccessListNew", "reqId", reqId, "err", errAL)
				}
			}
		}

		//--------access list

		state.Prepare(rules, from, coinbase, tx.To(), vm.ActivePrecompiles(rules), tx.AccessList())

		receipt, result, err := ApplyTransactionWithResult(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
		if err != nil {
			log.Info("CallBundleCheckBalance_12", "reqId", reqId, "err", err)
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		simulateBundleResultNew.GasUsed = receipt.GasUsed

		bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			simulateBundleResultNew.Error = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				reason, _ := abi.UnpackRevert(revert)
				simulateBundleResultNew.Revert = reason
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			simulateBundleResultNew.Value = ZeroX + string(dst)
		}
		// if simulation logs are requested append it to logs
		if args.SimulationLogs {
			simulateBundleResultNew.Logs = receipt.Logs
		}

		results = append(results, simulateBundleResultNew)

		//-------------------------------------------after
		if args.MevTokens != nil {
			if index == args.BalanceAfterIndex {
				balancesAfter, errBa := getTokenBalanceByContract(ctx, s, args.MevTokens, args.MevContract, state, header)
				if errBa != nil {
					log.Info("call_bundle_balance_err3", "reqId", reqId, "err", errBa)
					return nil, errBa
				}
				if len(args.MevTokens) != len(balancesAfter) {
					log.Info("call_bundle_balance_err4", "reqId", reqId, "mevTokens_len", len(args.MevTokens), "balances_len", len(balancesAfter))
					return nil, errors.New("call_bundle_balance_err4")
				}
				for i, mevTokenTmp := range args.MevTokens {

					var balancesAfterTmp *big.Int
					if mevTokenTmp.Cmp(WbnbAddress) == 0 {
						// balancesAfterTmp = new(big.Int).Add(balancesAfter[i], state.GetBalance(args.MevContract).ToBig())
						balancesAfterTmp = balancesAfter[i]
						log.Info("call_bundle_balance_after", "reqId", reqId, "mevTokenTmp", mevTokenTmp, "balancesAfterTmp", balancesAfterTmp, "bnbBalance", state.GetBalance(args.MevContract).ToBig())
					} else {
						balancesAfterTmp = balancesAfter[i]
					}

					checkBalanceResult := &CheckBalanceResult{
						BalanceType: "balancesAfter",
						Token:       mevTokenTmp,
						Balance:     balancesAfterTmp,
					}
					CheckBalanceResults = append(CheckBalanceResults, checkBalanceResult)
				}
			}
		}
		//-------------------------------------------after
	}

	var callTracerJsResults []*CallTracerJsResult

	if args.Pools != nil {
		callTracerJsResultsPool, poolErr := getPoolsInfo(ctx, reqId, s, args.Pools, state, header)
		if poolErr == nil {
			callTracerJsResults = append(callTracerJsResults, callTracerJsResultsPool...)
		}
	} else {
		//log.Info("call_bundle_pools_nil", "reqId", reqId)
	}

	if args.Pairs != nil {
		callTracerJsResultsPair, pairErr := getPairsInfo(ctx, reqId, s, args.Pairs, state, header)
		if pairErr == nil {
			callTracerJsResults = append(callTracerJsResults, callTracerJsResultsPair...)
		}
	} else {
		//log.Info("call_bundle_pairs_nil", "reqId", reqId)
	}

	callBundleResultNew := &CallBundleResultNew{
		ErrMsg:             "",
		Results:            results,
		BundleHash:         ZeroX + common.Bytes2Hex(bundleHash.Sum(nil)),
		CheckResults:       CheckBalanceResults,
		CallTracerJsResult: callTracerJsResults,
	}
	//newResultJson, _ := json.Marshal(callBundleResultNew)
	//log.Info("call_bundle_result_balance", "reqId", reqId, "ret", string(newResultJson))

	return callBundleResultNew, nil
}

const (
	ZeroX = "0x"
)

func getPairsInfo(ctx context.Context, reqId string, s *BundleAPI, pairs []*PairInfo, state *state.StateDB, header *types.Header) ([]*CallTracerJsResult, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Info("recover...getPairsInfo", "reqId", reqId)
		}
	}()

	//marshalPairs, _ := json.Marshal(pairs)
	//log.Info("call_getPairsInfo_start", "reqId", reqId, "pairs", string(marshalPairs))

	var callTracerJsResults []*CallTracerJsResult

	for _, pairInfo := range pairs {

		getReservesMethod := "getReserves"
		getReservesData := getMethodData(getReservesMethod)

		getReservesReturn, err := executeMethod(ctx, reqId, s, common.HexToAddress(pairInfo.Address), getReservesData, state, header)
		if err != nil {
			log.Info("call_getPairsInfo_err", "reqId", reqId, "pair", pairInfo.Address, "method", getReservesMethod, "return", common.Bytes2Hex(getReservesReturn), "err", err)
			continue
		}

		//log.Info("call_getPairsInfo_1", "reqId", reqId, "pair", pair.String(), "method", getReservesMethod, "return", common.Bytes2Hex(getReservesReturn))

		reserve0 := getReservesReturn[:32]
		reserve1 := getReservesReturn[32:64]

		callTracerJsResult := &CallTracerJsResult{
			Address:  pairInfo.Address,
			Reserve0: ZeroX + common.Bytes2Hex(reserve0),
			Reserve1: ZeroX + common.Bytes2Hex(reserve1),
			Type:     "v2",
		}
		callTracerJsResults = append(callTracerJsResults, callTracerJsResult)
		log.Info("call_getPairsInfo_success", "reqId", reqId, "pair", pairInfo.Address)

	}
	log.Info("call_getPairsInfo_finish", "reqId", reqId, "callTracerJsResults", len(callTracerJsResults))

	return callTracerJsResults, nil
}

func getMethodData(method string) hexutil.Bytes {
	newMethod := abi.NewMethod(method, method, abi.Function, "pure", false, false, nil, nil)
	bytes := (hexutil.Bytes)(newMethod.ID)
	return bytes
}

func getV4MethodData(methodName, address string) hexutil.Bytes {
	poolIdFixed, err := getPooID32Bytes(address)
	if err != nil {
		return nil
	}

	poolIdType, _ := abi.NewType("bytes32", "bytes32", nil)

	inArgument := []abi.Argument{
		{
			Name: "",
			Type: poolIdType,
		},
	}

	newMethod := abi.NewMethod(methodName, methodName, abi.Function, "pure", false, false, inArgument, nil)

	pack, err := newMethod.Inputs.Pack(poolIdFixed)
	if err != nil {
		return nil
	}

	var data hexutil.Bytes

	data = (hexutil.Bytes)(newMethod.ID)

	data = append(data, (hexutil.Bytes)(pack)...)

	log.Info("call_getV4MethodData_finish", "method", methodName, "address", address, "data", common.Bytes2Hex(data))

	return data
}

func getPoolsInfo(ctx context.Context, reqId string, s *BundleAPI, pools []*PoolInfo, state *state.StateDB, header *types.Header) ([]*CallTracerJsResult, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Info("recover...getPoolsInfo")
		}
	}()

	//marshalPairs, _ := json.Marshal(pools)
	//log.Info("call_getPoolsInfo_start", "reqId", reqId, "pools", string(marshalPairs))

	var callTracerJsResults []*CallTracerJsResult

	for _, poolInfo := range pools {

		var liquidity, sqrtPriceX96, tick string
		var err error
		if poolInfo.Version == 1 {
			liquidity, sqrtPriceX96, tick, err = getPoolInfoV3(ctx, reqId, s, poolInfo, state, header)
		} else if poolInfo.Version == 8 || poolInfo.Version == 9 {
			liquidity, sqrtPriceX96, tick, err = getPoolInfoV4(ctx, reqId, s, poolInfo, state, header)
		} else {
			continue
		}

		if err != nil {
			log.Info("call_getPoolsInfo_err", "reqId", reqId, "pool", poolInfo.Address, "version", poolInfo.Version, "err", err)
			continue
		}
		//-------------------------------------------------------------------------------------------

		callTracerJsResult := &CallTracerJsResult{
			Address:      poolInfo.Address,
			Liquidity:    liquidity,
			SqrtPriceX96: sqrtPriceX96,
			Tick:         tick,
			Type:         "v3",
		}
		callTracerJsResults = append(callTracerJsResults, callTracerJsResult)

		log.Info("call_getPoolsInfo_success", "reqId", reqId, "pool", poolInfo.Address, "version", poolInfo.Version)
	}
	log.Info("call_getPoolsInfo_finish", "reqId", reqId, "callTracerJsResults", len(callTracerJsResults))
	return callTracerJsResults, nil
}

func getPooID32Bytes(address string) ([32]byte, error) {

	poolId := address

	poolIdHex := strings.TrimPrefix(poolId, "0x")
	poolIdBytes, err := hex.DecodeString(poolIdHex)

	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid poolId hex string: %v", err)
	}
	if len(poolIdBytes) != 32 {
		return [32]byte{}, fmt.Errorf("poolId bytes length is not 32")
	}

	var poolIdFixed [32]byte
	copy(poolIdFixed[:], poolIdBytes)
	return poolIdFixed, nil
}

func getPoolInfoV4(ctx context.Context, reqId string, s *BundleAPI, poolInfo *PoolInfo, state *state.StateDB, header *types.Header) (string, string, string, error) {

	var liquidityToAddress common.Address
	if poolInfo.Version == 8 {
		liquidityToAddress = UniswapV4StateView
	} else if poolInfo.Version == 9 {
		liquidityToAddress = PancakeV4CLPoolManager
	} else {
		return "", "", "", errors.New("unknown poolInfo.Version")
	}

	liquidityMethod := "getLiquidity"
	liquidityData := getV4MethodData(liquidityMethod, poolInfo.Address)
	liquidityReturn, err := executeMethod(ctx, reqId, s, liquidityToAddress, liquidityData, state, header)
	if err != nil {
		log.Info("call_getPoolsInfo_v4_getLiquidity_err", "reqId", reqId, "pool", poolInfo.Address, "method", liquidityMethod, "return", common.Bytes2Hex(liquidityReturn), "err", err)
		return "", "", "", err
	}
	liquidity := ZeroX + common.Bytes2Hex(liquidityReturn)

	slot0Method := "getSlot0"
	slot0Data := getV4MethodData(slot0Method, poolInfo.Address)
	slot0Return, err := executeMethod(ctx, reqId, s, liquidityToAddress, slot0Data, state, header)
	if err != nil {
		log.Info("call_getPoolsInfo_v4_getSlot0_err", "reqId", reqId, "pool", poolInfo.Address, "method", slot0Method, "return", common.Bytes2Hex(slot0Return), "err", err)
		return "", "", "", err
	}

	sqrtPriceX96 := ZeroX + common.Bytes2Hex(slot0Return[:32])
	tick := ZeroX + common.Bytes2Hex(slot0Return[32:64])

	return liquidity, sqrtPriceX96, tick, nil
}

func getPoolInfoV3(ctx context.Context, reqId string, s *BundleAPI, poolInfo *PoolInfo, state *state.StateDB, header *types.Header) (string, string, string, error) {
	liquidityMethod := "liquidity"
	liquidityData := getMethodData(liquidityMethod)
	liquidityReturn, err := executeMethod(ctx, reqId, s, common.HexToAddress(poolInfo.Address), liquidityData, state, header)
	if err != nil {
		log.Info("call_getPoolsInfo_v3_getLiquidity_err", "reqId", reqId, "pool", poolInfo.Address, "method", liquidityMethod, "return", common.Bytes2Hex(liquidityReturn), "err", err)
		return "", "", "", err
	}
	//log.Info("call_getPoolsInfo_1", "reqId", reqId, "pool", pool.String(), "method", liquidityMethod, "return", common.Bytes2Hex(liquidityReturn), "err", err)
	liquidity := ZeroX + common.Bytes2Hex(liquidityReturn)
	//-------------------------------------------------------------------------------------------

	var sqrtPriceX96, tick string
	slot0Method := "slot0"
	slot0Data := getMethodData(slot0Method)
	slot0Return, err := executeMethod(ctx, reqId, s, common.HexToAddress(poolInfo.Address), slot0Data, state, header)
	if err != nil {
		globalStateMethod := "globalState"
		globalStateData := getMethodData(globalStateMethod)
		slot0Return, err = executeMethod(ctx, reqId, s, common.HexToAddress(poolInfo.Address), globalStateData, state, header)
		if err != nil {
			return "", "", "", err
		}
	}
	sqrtPriceX96 = ZeroX + common.Bytes2Hex(slot0Return[:32])
	tick = ZeroX + common.Bytes2Hex(slot0Return[32:64])

	return liquidity, sqrtPriceX96, tick, nil
}

func executeMethod(ctx context.Context, reqId string, s *BundleAPI, poolorPair common.Address, data hexutil.Bytes, state *state.StateDB, header *types.Header) ([]byte, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Info("recover...executeMethod")
		}
	}()

	reqId += "_executeMethod_" + poolorPair.String()

	callArgs := &TransactionArgs{
		To:   &poolorPair,
		Data: &data,
	}
	callResult, err := mevCall(reqId, state, header, s, ctx, callArgs, nil, nil, nil)

	if err != nil {
		log.Info("call_executeMethod4", "reqId", reqId, "err", err)
		return nil, err
	}

	if callResult == nil {
		log.Info("call_executeMethod5", "reqId", reqId)
		return nil, errors.New("callResult_nil")
	}

	//log.Info("call_executeMethod6", "reqId", reqId, "result", common.Bytes2Hex(callResult.ReturnData))

	if len(callResult.Revert()) > 0 {

		revertReason := newRevertError(callResult.Revert())
		log.Info("call_result_not_nil_44",
			"reqId", reqId,
			"data", callResult,
			"revert", common.Bytes2Hex(callResult.Revert()),
			"revertReason", revertReason,
			"returnData", common.Bytes2Hex(callResult.Return()),
		)
		return nil, revertReason
	}

	if callResult.Err != nil {
		log.Info("call_executeMethod8", "reqId", reqId, "err", callResult.Err)
		return nil, callResult.Err
	}

	//log.Info("call_executeMethod_finish")
	return callResult.Return(), nil
}
