package case03

type RecordRepository struct {
	records map[string]Record
}

func (repository RecordRepository) Find(id string, _ string) Record {
	return repository.records[id]
}
