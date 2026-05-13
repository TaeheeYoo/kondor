// SPDX-License-Identifier: GPL-2.0
package server

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/patchwork-systems/kondor/internal/lb"
	"github.com/patchwork-systems/kondor/internal/model"
)

type handler struct {
	mgr *lb.Manager
}

func (h *handler) listVIPs(c *gin.Context) {
	c.JSON(http.StatusOK, h.mgr.ListVIPs())
}

type addVIPRequest struct {
	Address  string       `json:"address" binding:"required"`
	Port     uint16       `json:"port" binding:"required"`
	Protocol string       `json:"protocol" binding:"required"`
	Reals    []realEntry  `json:"reals"`
	Flags    uint32       `json:"flags"`
}

type realEntry struct {
	Address string `json:"address" binding:"required"`
	Weight  int    `json:"weight"`
}

func (h *handler) addVIP(c *gin.Context) {
	var req addVIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg := model.VIPConfig{
		VIP: model.VIP{
			Address:  net.ParseIP(req.Address).To4(),
			Port:     req.Port,
			Protocol: req.Protocol,
		},
		Flags: req.Flags,
	}

	for _, r := range req.Reals {
		cfg.Reals = append(cfg.Reals, model.Real{
			Address: net.ParseIP(r.Address).To4(),
			Weight:  r.Weight,
		})
	}

	if err := h.mgr.AddVIP(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": "ok"})
}

type deleteVIPRequest struct {
	Address  string `json:"address" binding:"required"`
	Port     uint16 `json:"port" binding:"required"`
	Protocol string `json:"protocol" binding:"required"`
}

func (h *handler) deleteVIP(c *gin.Context) {
	var req deleteVIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vip := model.VIP{
		Address:  net.ParseIP(req.Address).To4(),
		Port:     req.Port,
		Protocol: req.Protocol,
	}

	if err := h.mgr.DeleteVIP(vip); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type addRealRequest struct {
	VIPAddress  string `json:"vip_address" binding:"required"`
	VIPPort     uint16 `json:"vip_port" binding:"required"`
	VIPProtocol string `json:"vip_protocol" binding:"required"`
	RealAddress string `json:"real_address" binding:"required"`
}

func (h *handler) addReal(c *gin.Context) {
	var req addRealRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vip := model.VIP{
		Address:  net.ParseIP(req.VIPAddress).To4(),
		Port:     req.VIPPort,
		Protocol: req.VIPProtocol,
	}
	real := model.Real{
		Address: net.ParseIP(req.RealAddress).To4(),
	}

	if err := h.mgr.AddReal(vip, real); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": "ok"})
}

type deleteRealRequest struct {
	VIPAddress  string `json:"vip_address" binding:"required"`
	VIPPort     uint16 `json:"vip_port" binding:"required"`
	VIPProtocol string `json:"vip_protocol" binding:"required"`
	RealAddress string `json:"real_address" binding:"required"`
}

func (h *handler) deleteReal(c *gin.Context) {
	var req deleteRealRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vip := model.VIP{
		Address:  net.ParseIP(req.VIPAddress).To4(),
		Port:     req.VIPPort,
		Protocol: req.VIPProtocol,
	}

	if err := h.mgr.DeleteReal(vip, net.ParseIP(req.RealAddress).To4()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type statsRequest struct {
	Address  string `form:"address" binding:"required"`
	Port     uint16 `form:"port" binding:"required"`
	Protocol string `form:"protocol" binding:"required"`
}

func (h *handler) getStats(c *gin.Context) {
	var req statsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vip := model.VIP{
		Address:  net.ParseIP(req.Address).To4(),
		Port:     req.Port,
		Protocol: req.Protocol,
	}

	stats, err := h.mgr.GetStats(vip)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

func (h *handler) getGlobalStats(c *gin.Context) {
	c.JSON(http.StatusOK, h.mgr.GetGlobalStats())
}
