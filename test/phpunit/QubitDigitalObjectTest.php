<?php

class QubitDigitalObjectTest extends \PHPUnit\Framework\TestCase
{
    public function testHasFfmpeg()
    {
        $result = QubitDigitalObject::hasFfmpeg();
        $this->assertTrue($result);
    }

    public function testHasFfprobe()
    {
        $result = QubitDigitalObject::hasFfprobe();
        $this->assertTrue($result);
    }

    // convertVideoToMP4 Tests
    public function testConvertVideoToMp4_FfmpegNotAvailable()
    {
        $mock = $this->getMockBuilder(QubitDigitalObject::class)
            ->onlyMethods(['hasFfmpeg'])
            ->getMock();

        $mock->expects($this->once())->method('hasFfmpeg')->willReturn(false);

        $result = $mock->convertVideoToMp4('input.avi', 'output.mp4');
        $this->assertFalse($result);
    }

    public function testConvertVideoToMp4_NoReencodingNeeded()
    {
        $mock = $this->getMockBuilder(QubitDigitalObject::class)
            ->onlyMethods(['hasFfmpeg', 'readStreamInformation', 'isFastStarted'])
            ->getMock();

        $mock->method('hasFfmpeg')->willReturn(true);
        $mock->method('readStreamInformation')->willReturn([
            'video' => ['codec_name' => 'h264', 'pix_fmt' => 'yuv420p'],
            'audio' => ['codec_name' => 'aac', 'sample_rate' => 44100],
            'format_name' => 'mp4'
        ]);
        $mock->method('isFastStarted')->willReturn(true);

        $mock->expects($this->once())->method('copy')->with('input.avi', 'output.mp4');

        $result = $mock->convertVideoToMp4('input.avi', 'output.mp4');
        $this->assertTrue($result);
    }

    public function testConvertVideoToMp4_ReencodeBothAudioAndVideo()
    {
        $mock = $this->getMockBuilder(QubitDigitalObject::class)
            ->onlyMethods(['hasFfmpeg', 'readStreamInformation', 'isFastStarted'])
            ->getMock();

        $mock->method('hasFfmpeg')->willReturn(true);
        $mock->method('readStreamInformation')->willReturn([
            'video' => ['codec_name' => 'vp9', 'pix_fmt' => 'yuv444p'],
            'audio' => ['codec_name' => 'mp3', 'sample_rate' => 48000],
            'format_name' => 'avi'
        ]);
        $mock->method('isFastStarted')->willReturn(false);

        $expectedCommand = "ffmpeg -y -i 'input.avi' -c:v libx264 -pix_fmt yuv420p -c:a aac -ar 44100 'output.mp4' -movflags faststart 2>&1";
        $this->expectExec($expectedCommand);

        $result = $mock->convertVideoToMp4('input.avi', 'output.mp4');
        $this->assertTrue($result);
    }

}