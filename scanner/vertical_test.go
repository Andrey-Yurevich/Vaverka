package scanner

import (
	"Vaverka/rule"
	"fmt"
	"testing"
)

// TestVerticalPortScanner tests the VerticalPortScanner function for the network 10.0.0.0/8.
func TestVerticalPortScanner(t *testing.T) {
	// Подготовка тестового правила для сканирования сети 10.0.0.0/8
	ruleString := "10.0.0.0/12" // Сеть для сканирования
	testRule, err := rule.ParseRule(ruleString)
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	// Добавляем порты для сканирования (например, 80, 443)
	testRule.Ports = []uint16{}

	// Запуск сканирования
	fmt.Printf("Starting VerticalPortScanner for network %s\n", ruleString)
	err = VerticalPortScanner(testRule)
	if err != nil {
		t.Errorf("VerticalPortScanner failed: %v", err)
	}

	// Проверка результатов
	fmt.Println("VerticalPortScanner completed successfully for network", ruleString)
}
