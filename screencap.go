package libadb

import (
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
)

func SaveImageAsFile(img image.Image, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("无法创建文件 %s：%v", filename, err)
	}
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		log.Fatalf("无法将图像编码为 PNG 格式并写入文件 %s：%v", filename, err)
	}

	log.Printf("图像已成功保存为 %s", filename)
}

func convertRGB16ToImage(data []byte, width, height int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			index := (y*width + x) * 2
			r := uint8(data[index])
			g := uint8((data[index]>>8)&0xF8) | uint8((data[index+1]>>5)&0x07)
			b := uint8(data[index+1] << 3)
			img.Set(x, y, color.RGBA{r, g, b, 255})
		}
	}
	return img
}
func convertBGRA_8888ToImage(bgraData []byte, width, height int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	dataLen := len(bgraData)
	// 填充 image.RGBA 对象
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			index := (y*width + x) * 4
			if index >= dataLen {
				break // 如果超出数据范围，则停止填充
			}

			b := bgraData[index+0]
			g := bgraData[index+1]
			r := bgraData[index+2]
			a := bgraData[index+3]

			colorRGBA := color.RGBA{r, g, b, a}
			img.Set(x, y, colorRGBA)
		}
	}
	return img
}

func convertRGBA888ToImage(rgbaData []byte, width, height int) *image.RGBA {
	// 计算数据大小
	dataLen := len(rgbaData)

	// 创建一个 image.RGBA 对象
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// 填充 image.RGBA 对象
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			index := (y*width + x) * 4
			if index >= dataLen {
				break // 如果超出数据范围，则停止填充
			}

			r := rgbaData[index+0]
			g := rgbaData[index+1]
			b := rgbaData[index+2]
			a := rgbaData[index+3]

			colorRGBA := color.RGBA{r, g, b, a}
			img.Set(x, y, colorRGBA)
		}
	}
	return img
}

func convertRGBX_8888ToImage(rgbxData []byte, width, height int) *image.RGBA {
	// 创建一个 image.RGBA 对象
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	dataLen := len(rgbxData)
	// 填充 image.RGBA 对象
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			index := (y*width + x) * 4
			if index >= dataLen {
				break // 如果超出数据范围，则停止填充
			}

			r := rgbxData[index+0]
			g := rgbxData[index+1]
			b := rgbxData[index+2]
			a := 255 // 完全不透明
			colorRGBA := color.RGBA{r, g, b, uint8(a)}
			img.Set(x, y, colorRGBA)
		}
	}
	return img
}
func convertRGB_888ToImage(rgbData []byte, width, height int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	dataLen := len(rgbData)
	// 填充 image.RGBA 对象
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			index := (y*width + x) * 3
			if index >= dataLen {
				break // 如果超出数据范围，则停止填充
			}

			r := rgbData[index+0]
			g := rgbData[index+1]
			b := rgbData[index+2]
			a := 255 // 完全不透明

			colorRGBA := color.RGBA{r, g, b, uint8(a)}
			img.Set(x, y, colorRGBA)
		}
	}
	return img
}
func (adbClient *AdbClient) Screencap() (*image.RGBA, error) {
	if adbClient.AdbConn == nil {
		return nil, errors.New("not connect")
	}
	adbClient.LocalId++
	// Send OPEN
	var shell_cmd = "framebuffer:"
	var open_message = generate_message(A_OPEN, adbClient.LocalId, 0, []byte(shell_cmd))
	adbClient.AdbConn.Write(open_message)

	// Read OKAY
	message, _ := message_parse(adbClient.AdbConn)
	if message.command != uint32(A_OKAY) {
		log.Println("Not OKAY command")
		return nil, errors.New("Not OKAY command")
	}
	remoteId := int32(message.arg0)
	// Read WRTE
	message, _ = message_parse(adbClient.AdbConn)
	if message.command != uint32(A_WRTE) {
		log.Println("Not WRTE command")
		return nil, errors.New("Not OKAY command")
	}

	var fBuf []byte
	var okay_message = generate_message(A_OKAY, adbClient.LocalId, remoteId, []byte{})
	adbClient.AdbConn.Write(okay_message)
	fBuf = append(fBuf, message.payload...)
	for {
		// Send OKAY
		okay_message = generate_message(A_OKAY, adbClient.LocalId, remoteId, []byte{})
		adbClient.AdbConn.Write(okay_message)
		msg, _ := message_parse(adbClient.AdbConn)
		//fmt.Printf("msg%+v\r\n", msg)
		if msg.command != uint32(A_WRTE) {
			break
		}
		fBuf = append(fBuf, msg.payload...)
	}

	//read head
	version := binary.LittleEndian.Uint32(fBuf[:4])
	var f Framebuffer_headV1
	var imgBuf []byte
	if version == 1 {
		imgBuf = message.payload[52:]
		f.bpp = binary.LittleEndian.Uint32(fBuf[4:8])
		f.size = binary.LittleEndian.Uint32(fBuf[8:12])
		f.width = binary.LittleEndian.Uint32(fBuf[12:16])
		f.height = binary.LittleEndian.Uint32(fBuf[16:20])
		f.red_offset = binary.LittleEndian.Uint32(fBuf[20:24])
		f.alpha_length = binary.LittleEndian.Uint32(fBuf[48:52])
	}
	if version == 2 {
		imgBuf = fBuf[56:]
		f.bpp = binary.LittleEndian.Uint32(fBuf[4:8])
		f.size = binary.LittleEndian.Uint32(fBuf[12:16])
		f.width = binary.LittleEndian.Uint32(fBuf[16:20])
		f.height = binary.LittleEndian.Uint32(fBuf[20:24])
		f.red_offset = binary.LittleEndian.Uint32(fBuf[24:28])
		f.alpha_length = binary.LittleEndian.Uint32(fBuf[52:56])
	}
	var img *image.RGBA
	if f.bpp == 16 {
		//RGB_565
		img = convertRGB16ToImage(imgBuf, int(f.width), int(f.height))
		return img, nil
	} else if f.bpp == 24 {
		//RGB_888
		img = convertRGB_888ToImage(imgBuf, int(f.width), int(f.height))
		return img, nil
	} else if f.bpp == 32 {
		//BGRA_8888
		if f.red_offset == 16 {

			img = convertBGRA_8888ToImage(imgBuf, int(f.width), int(f.height))
			return img, nil
		}

		if f.red_offset == 0 {
			//RGBX_8888
			if f.alpha_length == 0 {
				img = convertRGBX_8888ToImage(imgBuf, int(f.width), int(f.height))
				return img, nil
			}
			// RGBA_8888
			if f.alpha_length == 8 {
				img = convertRGBA888ToImage(imgBuf, int(f.width), int(f.height))
				return img, nil
			}
		}
	}
	return nil, errors.New("error")
}