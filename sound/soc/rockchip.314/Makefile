#TSAI: copied from Rockchip 3.14 kernel

# ROCKCHIP Platform Support
#TSAI: I use 3.10 rk_i2s.c instead of rockchip_i2s.c
snd-soc-i2s-objs := rk_i2s.o rk_pcm.o
obj-$(CONFIG_SND_SOC_ROCKCHIP_I2S) += snd-soc-i2s.o

# ROCKCHIP Machine Support
snd-soc-rockchip-rt5631-objs := rockchip_rt5631.o
snd-soc-rockchip-rt5640-objs := rockchip_rt5640.o
snd-soc-rockchip-max98090-objs := rockchip_max98090.o

obj-$(CONFIG_SND_SOC_ROCKCHIP_RT5631) += snd-soc-rockchip-rt5631.o
obj-$(CONFIG_SND_SOC_ROCKCHIP_RT5640) += snd-soc-rockchip-rt5640.o
obj-$(CONFIG_SND_SOC_ROCKCHIP_MAX98090) += snd-soc-rockchip-max98090.o
#TSAI: intentionally use 3.10 driver
obj-$(CONFIG_SND_SOC_ROCKCHIP_HDMI_AUDIO) += rk_hdmi_i2s.o

#TSAI: still need this 
obj-$(CONFIG_SND_RK_SOC_ES8316) += rk_es8316.o card_info.o


CFLAGS_rockchip_i2s.o += -O0
