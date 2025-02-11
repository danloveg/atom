<?php

class QubitDigitalObjectTest extends \PHPUnit\Framework\TestCase
{   
    private $qubitDigitalObject;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->qubitDigitalObject = $this->getMockBuilder(QubitDigitalObject::class)
            ->onlyMethods(['readStreamInformation', 'isFastStarted'])
            ->getMock();
    }

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

    // getConvertToMP4Command Tests
    public function commandDataProvider()
    {
        return [
            // 1. No re-encoding needed, already fast-started
            [
                'input.mp4',
                [   
                    'format_name' => 'mp4',
                    'video' => ['codec_name' => 'h264', 'pix_fmt' => 'yuv420p'],
                    'audio' => ['codec_name' => 'aac', 'sample_rate' => 44100], 
                ],
                true,
                ''
            ],
            
            // // 2. Video needs re-encoding (wrong video codec), audio is fine
            
            // // 3. Audio needs re-encoding, video is fine
            
            // // 4. Both video and audio need re-encoding
        
            
            // // 5. Only fast-start needed, no re-encoding
           
        ];
    }

    /**
     * @dataProvider commandDataProvider
     */
    public function testGetConvertToMp4Command($inputPath, $streamInfo, $isFastStarted, $expectedCommand)
    {   
        $this->qubitDigitalObject->method('readStreamInformation')
            ->willReturn($streamInfo);

        $this->qubitDigitalObject->method('isFastStarted')
            ->willReturn($isFastStarted);

        $command = $this->qubitDigitalObject->getConvertToMp4Command($inputPath, 'output.mp4');
        $this->assertEquals($expectedCommand, $command);
    }
    

}