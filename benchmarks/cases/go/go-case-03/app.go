package case03

import "strings"

type Record struct {
	Owner string
	Value string
}

func LoadRecord(records map[string]Record, id string, requestingUser string) Record {
	endpoint := RecordEndpoint{service: NewRecordService(records)}
	return endpoint.Get(RecordRequest{ID: strings.TrimSpace(id), RequestingUser: requestingUser})
}

type RecordRequest struct {
	ID             string
	RequestingUser string
}

type RecordEndpoint struct {
	service RecordService
}

func (endpoint RecordEndpoint) Get(request RecordRequest) Record {
	return endpoint.service.Load(request)
}
