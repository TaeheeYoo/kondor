// SPDX-License-Identifier: GPL-2.0
package server

import (
	"github.com/gin-gonic/gin"

	"github.com/patchwork-systems/kondor/internal/lb"
)

func New(mgr *lb.Manager) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	h := &handler{mgr: mgr}

	api := r.Group("/api/v1")
	{
		api.GET("/vips", h.listVIPs)
		api.POST("/vips", h.addVIP)
		api.DELETE("/vips", h.deleteVIP)

		api.POST("/vips/reals", h.addReal)
		api.DELETE("/vips/reals", h.deleteReal)

		api.GET("/stats", h.getStats)
		api.GET("/stats/global", h.getGlobalStats)
	}

	return r
}
