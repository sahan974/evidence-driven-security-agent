package fixture

import "testing"

func TestRaceDetectorTarget(t *testing.T) {
	value := 0
	done := make(chan bool, 2)
	for index := 0; index < 2; index++ {
		go func() {
			value++
			done <- true
		}()
	}
	<-done
	<-done
	_ = value
}
