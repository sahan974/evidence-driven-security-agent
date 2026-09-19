package case03

type RecordService struct {
	repository RecordRepository
}

func NewRecordService(records map[string]Record) RecordService {
	return RecordService{repository: RecordRepository{records: records}}
}

func (service RecordService) Load(request RecordRequest) Record {
	return service.repository.Find(request.ID, request.RequestingUser)
}
