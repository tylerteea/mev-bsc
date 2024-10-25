package ethapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"
	"math"
	"math/big"
	"runtime/debug"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

type CallBundleCheckAndPoolPairStateArgs struct {
	Txs                    []hexutil.Bytes       `json:"txs"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber"`
	Coinbase               *string               `json:"coinbase"`
	Timestamp              *uint64               `json:"timestamp"`
	Timeout                *int64                `json:"timeout"`
	GasLimit               *uint64               `json:"gasLimit"`
	Difficulty             *big.Int              `json:"difficulty"`
	SimulationLogs         bool                  `json:"simulationLogs"`
	StateOverrides         *StateOverride        `json:"stateOverrides"`
	BaseFee                *big.Int              `json:"baseFee"`

	MevContract    common.Address   `json:"mevContract,omitempty"`
	MevTokens      []common.Address `json:"mevTokens,omitempty"`
	Pairs          []common.Address `json:"pairs,omitempty"`
	Pools          []common.Address `json:"pools,omitempty"`
	ReqId          string           `json:"reqId"`
	NeedAccessList []bool           `json:"need_access_list"`
}

func (s *BundleAPI) CallBundleCheckAndPoolPairState(ctx context.Context, args CallBundleCheckAndPoolPairStateArgs) (map[string]interface{}, error) {

	reqId := args.ReqId

	defer func(start time.Time) {
		if r := recover(); r != nil {
			dss := string(debug.Stack())
			log.Info("recover...CallBundleCheckBalance", "err", r, "stack", dss, "reqId", reqId)
		}

		log.Info("CallBundleCheckBalance_end_defer", "reqId", reqId, "runtime", time.Since(start))
	}(time.Now())

	log.Info("CallBundleCheckBalance_0", "reqId", reqId)

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

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)
	stateHead, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if stateHead == nil || err != nil {
		return nil, err
	}
	// 避免相互影响
	state := stateHead.Copy()

	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
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

	results := []map[string]interface{}{}

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), blockNumber, header.Time)
	var totalGasUsed uint64
	gasFees := new(big.Int)

	isPostMerge := header.Difficulty.Cmp(common.Big0) == 0
	rules := s.b.ChainConfig().Rules(header.Number, isPostMerge, header.Time)

	//-------------------------------------------

	checkResult := map[string]interface{}{}

	if args.MevTokens != nil {
		balancesBefore, err11 := getTokenBalanceByContract(ctx, s, args.MevTokens, args.MevContract, state, header)

		if err11 != nil {
			log.Info("call_bundle_balance_err1", "reqId", reqId, "err", err11)
			return nil, err11
		}

		if len(args.MevTokens) != len(balancesBefore) {
			log.Info("call_bundle_balance_err2", "reqId", reqId, "mevTokens_len", len(args.MevTokens), "balances_len", len(balancesBefore), "err", err)
			return nil, err11
		}

		balancesBeforeMap := make(map[common.Address]*big.Int)
		for i, mevTokenTmp := range args.MevTokens {
			balancesBeforeMap[mevTokenTmp] = balancesBefore[i]
		}
		checkResult["balancesBefore"] = balancesBeforeMap
	}

	//-------------------------------------------

	for index, tx := range txs {

		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			log.Info("CallBundleCheckBalance_8", "reqId", reqId, "err", err)
			return nil, err
		}

		from, err := types.Sender(signer, tx)

		to := "0x"
		if tx.To() != nil {
			to = tx.To().String()
		}
		jsonResult := map[string]interface{}{
			"txHash":      tx.Hash().String(),
			"fromAddress": from.String(),
			"toAddress":   to,
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

				accessList, errAL := createAccessListNew(ctx, s.b, callArgs, &args.StateBlockNumberOrHash, state, header)

				if errAL == nil && accessList != nil {

					accessListGasUsed := uint64(accessList.GasUsed)

					jsonResult["accessListGasUsed"] = accessListGasUsed
					jsonResult["accessListResult"] = accessList.Accesslist

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

		if err != nil {
			log.Info("call_bundle_balance_err14", "reqId", reqId, "err", err)
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		jsonResult["gasUsed"] = receipt.GasUsed

		totalGasUsed += receipt.GasUsed

		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			log.Info("CallBundleCheckBalance_16", "reqId", reqId, "err", err)
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)

		// gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), tx.GasPrice())
		gasFees.Add(gasFees, gasFeesTx)
		bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			jsonResult[errorString] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				reason, _ := abi.UnpackRevert(revert)
				jsonResult["revert"] = reason
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			jsonResult["value"] = "0x" + string(dst)
		}
		// if simulation logs are requested append it to logs
		if args.SimulationLogs {
			jsonResult["logs"] = receipt.Logs
		}

		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["gasUsed"] = receipt.GasUsed

		results = append(results, jsonResult)
	}

	//-------------------------------------------
	if args.MevTokens != nil {
		balancesAfter, err := getTokenBalanceByContract(ctx, s, args.MevTokens, args.MevContract, state, header)

		if err != nil {
			log.Info("call_bundle_balance_err3", "reqId", reqId, "err", err)
			return nil, err
		}

		if len(args.MevTokens) != len(balancesAfter) {
			log.Info("call_bundle_balance_err4", "reqId", reqId, "mevTokens_len", len(args.MevTokens), "balances_len", len(balancesAfter), "err", err)
			return nil, err
		}

		balancesAfterMap := make(map[common.Address]*big.Int)

		for i, mevTokenTmp := range args.MevTokens {
			balancesAfterMap[mevTokenTmp] = balancesAfter[i]
		}
		checkResult["balancesAfter"] = balancesAfterMap
	}

	ret := map[string]interface{}{}

	ret["errMsg"] = ""
	ret["results"] = results
	ret["stateBlockNumber"] = header.Number.Int64()
	ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))

	ret["check_result"] = checkResult

	newResultJson, _ := json.Marshal(ret)
	log.Info("call_bundle_result_balance", "reqId", reqId, "ret", string(newResultJson))

	return ret, nil
}

func getPoolInfo(ctx context.Context, s *BundleAPI, token common.Address, account common.Address, state *state.StateDB, header *types.Header) (*big.Int, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Info("recover...getERC20TokenBalance")
		}
	}()

	reqId := "getERC20TokenBalance_" + token.String() + "_" + account.String()

	newMethod := abi.NewMethod("balanceOf", "balanceOf", abi.Function, "pure", false, false, inp, oup)
	pack, err := newMethod.Inputs.Pack(account)
	var data = append(newMethod.ID, pack...)
	bytes := (hexutil.Bytes)(data)

	callArgs := &TransactionArgs{
		To:   &token,
		Data: &bytes,
	}
	callResult, err := mevCall(reqId, state, header, s, ctx, callArgs, nil, nil, nil)

	if callResult != nil {

		log.Info("call_execute4", "reqId", reqId, "result", string(callResult.ReturnData))
		if len(callResult.Revert()) > 0 {

			revertReason := newRevertError(callResult.Revert())
			log.Info("call_result_not_nil_44",
				"reqId", reqId,
				"data", callResult,
				"revert", common.Bytes2Hex(callResult.Revert()),
				"revertReason", revertReason,
				"returnData", common.Bytes2Hex(callResult.Return()),
			)
			log.Info("call_execute5", "reqId", reqId, "revertReason", revertReason.reason)
			return nil, revertReason
		}

		if callResult.Err != nil {
			log.Info("call_execute7", "reqId", reqId, "err", callResult.Err)
			return nil, callResult.Err
		}
	}
	if err != nil {
		log.Info("call_execute6", "reqId", reqId, "err", err)
		return nil, err
	}

	balance := new(big.Int).SetBytes(callResult.Return())
	log.Info("call_balance_finish", "reqId", reqId, "balance", balance.String())

	return balance, nil
}

func getPairInfo(ctx context.Context, s *BundleAPI, token common.Address, account common.Address, state *state.StateDB, header *types.Header) (*big.Int, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Info("recover...getERC20TokenBalance")
		}
	}()

	reqId := "getERC20TokenBalance_" + token.String() + "_" + account.String()

	newMethod := abi.NewMethod("balanceOf", "balanceOf", abi.Function, "pure", false, false, inp, oup)
	pack, err := newMethod.Inputs.Pack(account)
	var data = append(newMethod.ID, pack...)
	bytes := (hexutil.Bytes)(data)

	callArgs := &TransactionArgs{
		To:   &token,
		Data: &bytes,
	}
	callResult, err := mevCall(reqId, state, header, s, ctx, callArgs, nil, nil, nil)

	if callResult != nil {

		log.Info("call_execute4", "reqId", reqId, "result", string(callResult.ReturnData))
		if len(callResult.Revert()) > 0 {

			revertReason := newRevertError(callResult.Revert())
			log.Info("call_result_not_nil_44",
				"reqId", reqId,
				"data", callResult,
				"revert", common.Bytes2Hex(callResult.Revert()),
				"revertReason", revertReason,
				"returnData", common.Bytes2Hex(callResult.Return()),
			)
			log.Info("call_execute5", "reqId", reqId, "revertReason", revertReason.reason)
			return nil, revertReason
		}

		if callResult.Err != nil {
			log.Info("call_execute7", "reqId", reqId, "err", callResult.Err)
			return nil, callResult.Err
		}
	}
	if err != nil {
		log.Info("call_execute6", "reqId", reqId, "err", err)
		return nil, err
	}

	balance := new(big.Int).SetBytes(callResult.Return())
	log.Info("call_balance_finish", "reqId", reqId, "balance", balance.String())

	return balance, nil
}
