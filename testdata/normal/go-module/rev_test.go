package rev

import "testing"

func TestReverse(t *testing.T) {
	if Reverse("abc") != "cba" {
		t.Fatal(Reverse("abc"))
	}
}
