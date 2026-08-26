package case03

type Record struct { Owner string; Value string }

func LoadRecord(records map[string]Record, id string, _ string) Record {
	return records[id]
}
