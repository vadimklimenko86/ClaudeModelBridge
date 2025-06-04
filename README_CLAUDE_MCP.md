# MCP Server для Claude.ai

Этот сервер реализует протокол Model Context Protocol (MCP) для интеграции с Claude.ai.

## Возможности

- **Echo Tool**: Повторяет введенное сообщение
- **System Info**: Получает информацию о системе  
- **Calculator**: Выполняет математические вычисления

## Подключение к Claude.ai

### URL сервера
```
https://21d397d0-82f3-4fc2-893c-55bb08214050-00-1490hbmwtwihm.riker.replit.dev/mcp/
```

### Протокол
- **Версия**: 2024-11-05
- **Транспорт**: HTTP JSON-RPC 2.0
- **Методы**: initialize, tools/list, tools/call

### Примеры запросов

#### Инициализация
```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {}}
  },
  "id": 1
}
```

#### Список инструментов
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 2
}
```

#### Вызов инструмента
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "echo",
    "arguments": {"message": "Привет от Claude.ai!"}
  },
  "id": 3
}
```

## Статус

✅ Протокол MCP корректно реализован  
✅ Все инструменты функционируют  
✅ JSON-RPC 2.0 совместимость  
✅ CORS настроен для внешних подключений  
✅ Логирование запросов активно