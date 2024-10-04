package ethapi

import (
	"context"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

func (s *BundleAPI) GetNowValidators(ctx context.Context, number *rpc.BlockNumber) map[string]interface{} {

	log.Info("GetValidators_start", "number", number)

	result := make(map[string]interface{})

	result[errorString] = "default"
	result[reasonString] = "default"

	log.Info("初始化parliaAPI", "number", number)

	var blockNum *big.Int
	header := s.chain.CurrentHeader()
	if number == nil || *number == rpc.LatestBlockNumber {
		blockNum = header.Number
	} else if header.Number.Cmp(big.NewInt(number.Int64())) < 0 {

		blockNum = big.NewInt(number.Int64())
		mod := new(big.Int).Mod(blockNum, epochNum)

		nowEpoch := new(big.Int).Sub(blockNum, mod)
		nowEpoch.Add(nowEpoch, delayBlockNum)

		if blockNum.Cmp(nowEpoch) >= 0 && header.Number.Cmp(nowEpoch) < 0 {
			result[errorString] = "blockNum_out_of_epoch_limit"
			result[reasonString] = "当前header属于上个epoch，但blockNum属于下个epoch,无法预测此种情况"
			result["number"] = blockNum
			return result
		}

		if new(big.Int).Sub(blockNum, header.Number).Cmp(epochNum) > 0 {
			result[errorString] = "blockNum_great_header_200"
			result[reasonString] = "请求的块号比最新header大200块"
			result["number"] = blockNum
			return result
		}
	} else {
		header = s.chain.GetHeaderByNumber(uint64(number.Int64()))
		blockNum = header.Number
	}

	result["number"] = blockNum

	if header == nil {
		result[errorString] = "header_nil"
		result[reasonString] = "header_nil"
		return result
	}

	validators, err := s.b.Engine().GetNowValidators(s.chain, header)
	if err == nil {
		result[errorString] = ""
		result[reasonString] = ""
		result["validators"] = validators
	} else {
		result[errorString] = err
		result[reasonString] = err
	}

	marshal, _ := json.Marshal(result)
	log.Info("打印validators", "number", number, "validators", string(marshal))
	return result
}

func (s *BundleAPI) GetBuilderNew(ctx context.Context, number *rpc.BlockNumber) map[string]interface{} {

	startTime := time.Now()

	log.Info("GetBuilder_start1", "number", number)

	result := make(map[string]interface{})

	result["number"] = number
	result[errorString] = "default"
	result[reasonString] = "default"

	validatorResult := s.GetNowValidators(ctx, number)

	if validatorResult == nil || validatorResult[errorString] != "" {
		return validatorResult
	}

	blockNum, ok := validatorResult["number"].(*big.Int)
	if !ok {
		result[errorString] = "number_err"
		result[reasonString] = "number_err"
		result["number"] = blockNum
		marshal, _ := json.Marshal(result)
		log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())
		return validatorResult
	}

	mod := new(big.Int).Mod(blockNum, epochNum)

	nowEpoch := new(big.Int).Sub(blockNum, mod)
	nowEpoch.Add(nowEpoch, delayBlockNum)

	// 如果大于等于10，则预测到下一个epoch截止，如果小于10则使用当前epoch当截止
	var targetEpoch *big.Int
	if blockNum.Cmp(nowEpoch) >= 0 {
		targetEpoch = new(big.Int).Add(nowEpoch, epochNum)
	} else if blockNum.Cmp(nowEpoch) < 0 {
		targetEpoch = nowEpoch
	}

	result["number"] = blockNum

	if targetEpoch == nil {
		result[errorString] = "targetEpoch_nil"
		result[reasonString] = "targetEpoch_nil"
	} else {
		builderMap := make(map[int64]interface{})
		for i := blockNum.Int64(); i < targetEpoch.Int64(); i++ {

			blockNumber := rpc.BlockNumber(i)

			validatorRes := s.GetNowValidators(ctx, &blockNumber)

			if validatorRes == nil || validatorRes[errorString] != "" {
				log.Info("找不到验证者1", "number", i)
				continue
			}
			validatorsTmp, ok1 := validatorRes["validators"].(common.Address)

			if !ok1 {
				log.Info("找不到验证者2", "number", i)
				continue
			}
			builderMap[i] = validatorsTmp
			log.Info("找到验证者", "number", i, "builder", validatorsTmp)
		}
		result[errorString] = ""
		result[reasonString] = ""
		result["builderMap"] = builderMap
	}
	marshal, _ := json.Marshal(result)
	log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())

	return result
}

func (s *BundleAPI) GetBuilder(ctx context.Context, number *rpc.BlockNumber) map[string]interface{} {

	startTime := time.Now()

	log.Info("GetBuilder_start1", "number", number)

	result := make(map[string]interface{})

	result["number"] = number
	result[errorString] = "default"
	result[reasonString] = "default"

	validatorResult := s.GetNowValidators(ctx, number)

	if validatorResult == nil || validatorResult[errorString] != "" {
		return validatorResult
	}
	validators, ok := validatorResult["validators"].([]common.Address)

	if !ok {
		result[errorString] = "validator_err"
		result[reasonString] = "validator_err"
		marshal, _ := json.Marshal(result)
		log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())
		return validatorResult
	}

	blockNum, ok := validatorResult["number"].(*big.Int)
	if !ok {
		result[errorString] = "number_err"
		result[reasonString] = "number_err"
		result["number"] = blockNum
		marshal, _ := json.Marshal(result)
		log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())
		return validatorResult
	}

	mod := new(big.Int).Mod(blockNum, epochNum)

	nowEpoch := new(big.Int).Sub(blockNum, mod)
	nowEpoch.Add(nowEpoch, delayBlockNum)

	// 如果大于等于10，则预测到下一个epoch截止，如果小于10则使用当前epoch当截止
	var targetEpoch *big.Int
	if blockNum.Cmp(nowEpoch) >= 0 {
		targetEpoch = new(big.Int).Add(nowEpoch, epochNum)
	} else if blockNum.Cmp(nowEpoch) < 0 {
		targetEpoch = nowEpoch
	}

	result["number"] = blockNum

	if targetEpoch == nil {
		result[errorString] = "targetEpoch_nil"
		result[reasonString] = "targetEpoch_nil"
	} else {
		builderMap := make(map[uint64]interface{})
		for i := blockNum.Uint64(); i < targetEpoch.Uint64(); i++ {
			offset := (i + 1) % uint64(len(validators))
			builderMap[i] = validators[offset]
		}
		result[errorString] = ""
		result[reasonString] = ""
		result["builderMap"] = builderMap
	}
	marshal, _ := json.Marshal(result)
	log.Info("打印builder", "number", number, "builder", string(marshal), "cost_ms", time.Since(startTime).Milliseconds())

	return result
}
