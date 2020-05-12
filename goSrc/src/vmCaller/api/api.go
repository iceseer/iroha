package api

// #cgo CFLAGS: -I ../../../../irohad
// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
// #include "ametsuchi/impl/proto_command_executor.h"
// #include "ametsuchi/impl/proto_specific_query_executor.h"
import "C"
import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	pb "iroha.protocol"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/burrow/crypto"
)

var (
	IrohaCommandExecutor unsafe.Pointer
	IrohaQueryExecutor   unsafe.Pointer
	Caller               string
)

// -----------------------Iroha commands---------------------------------------

/*
	Transfer assets between accounts
*/
func TransferIrohaAsset(src, dst, asset, amount string) error {
	command := &pb.Command{Command: &pb.Command_TransferAsset{
		TransferAsset: &pb.TransferAsset{
			SrcAccountId:  src,
			DestAccountId: dst,
			AssetId:       asset,
			Description:   "EVM asset transfer",
			Amount:        amount,
		}}}
	commandResult, err := makeProtobufCmdAndExecute(IrohaCommandExecutor, command)
	if err != nil {
		return err
	}
	fmt.Println(commandResult)
	if commandResult.error_code != 0 {
		return fmt.Errorf("[api.TransferIrohaAsset] error transferring asset nominated in %s from %s to %s", asset, src, dst)
	}

	return nil
}

// -----------------------Iroha queries---------------------------------------

// Queries asset balance of an account
func GetIrohaAccountAssets(accountID string) ([]*pb.AccountAsset, error) {
	query := &pb.Query{Payload: &pb.Query_Payload{
		Meta: &pb.QueryPayloadMeta{
			CreatedTime:      uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			CreatorAccountId: Caller,
			QueryCounter:     1},
		Query: &pb.Query_Payload_GetAccountAssets{
			GetAccountAssets: &pb.GetAccountAssets{AccountId: accountID}}}}
	queryResponse, err := makeProtobufQueryAndExecute(IrohaQueryExecutor, query)
	if err != nil {
		return []*pb.AccountAsset{}, err
	}
	switch response := queryResponse.Response.(type) {
	case *pb.QueryResponse_ErrorResponse:
		if response.ErrorResponse.Reason == pb.ErrorResponse_NO_ACCOUNT {
			// No errors, but requested account does not exist
			return []*pb.AccountAsset{}, nil
		}
		return []*pb.AccountAsset{}, fmt.Errorf(
			"ErrorResponse in GetIrohaAccountAssets: %d, %v",
			response.ErrorResponse.ErrorCode,
			response.ErrorResponse.Message,
		)
	case *pb.QueryResponse_AccountAssetsResponse:
		accountAssetsResponse := queryResponse.GetAccountAssetsResponse()
		return accountAssetsResponse.AccountAssets, nil
	default:
		return []*pb.AccountAsset{}, fmt.Errorf("Wrong response type in GetIrohaAccountAssets")
	}
}

// -----------------------Helper functions---------------------------------------

// Execute Iroha command
func makeProtobufCmdAndExecute(cmdExecutor unsafe.Pointer, command *pb.Command) (res *C.struct_Iroha_CommandError, err error) {
	fmt.Println(proto.MarshalTextString(command))
	out, err := proto.Marshal(command)
	if err != nil {
		fmt.Println(err)
		// magic constant, if not 0 => fail happened
		return &C.struct_Iroha_CommandError{error_code: 100}, err
	}
	cOut := C.CBytes(out)
	commandResult := C.Iroha_ProtoCommandExecutorExecute(cmdExecutor, cOut, C.int(len(out)), C.CString(Caller))
	return &commandResult, nil
}

// Perform Iroha query
func makeProtobufQueryAndExecute(queryExecutor unsafe.Pointer, query *pb.Query) (res *pb.QueryResponse, err error) {
	fmt.Println(proto.MarshalTextString(query))
	out, err := proto.Marshal(query)
	if err != nil {
		fmt.Println(err)
	}
	cOut := C.CBytes(out)
	queryResult := C.Iroha_ProtoSpecificQueryExecutorExecute(queryExecutor, cOut, C.int(len(out)))
	fmt.Println(queryResult)
	out = C.GoBytes(queryResult.data, queryResult.size)
	queryResponse := &pb.QueryResponse{}
	err = proto.Unmarshal(out, queryResponse)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return queryResponse, nil
}

func (res *C.struct_Iroha_CommandError) String() string {
	if res.error_extra != nil {
		return fmt.Sprintf("%d, %s", res.error_code, C.GoString(res.error_extra))
	} else {
		return fmt.Sprintf("Iroha_CommandError: code %d", res.error_code)
	}
}

// Helper functions to convert 40 byte long EVM hex-encoded addresses to Iroha compliant account names (32 bytes max)
func irohaCompliantName(addr crypto.Address) string {
	s := strings.ToLower(addr.String())
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

func IrohaAccountID(addr crypto.Address) string {
	return irohaCompliantName(addr) + "@evm"
}
