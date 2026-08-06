package common

import (
	"time"

	"github.com/gorilla/websocket"
)

func CloseWS(ws *websocket.Conn) {
	if ws == nil {
		return
	}
	ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second))
	ws.Close()
}
