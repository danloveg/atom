<?php

use AccessToMemory\test\TransactionTestCase;
use org\bovigo\vfs\vfsStream;

/**
 * @covers \QubitDigitalObject
 *
 * @internal
 */
class QubitDigitalObjectTest extends TransactionTestCase
{
    protected $vfs;

    public function setUp(): void
    {
        parent::setUp();

        if (!extension_loaded('imagick')) {
            $this->markTestSkipped('The imagick extension is not available.');
        }

        $this->vfs = vfsStream::setup('testDir');
        sfConfig::set('sf_web_dir', vfsStream::url('testDir'));
    }

    /**
     * Test getting number of pages for a single image.
     *
     * @dataProvider validImagesProvider
     *
     * @param string $image
     */
    public function testGetPageCountImage($image)
    {
        $digitalObject = $this->newDigitalObject($image);

        $pageCount = $digitalObject->getPageCount();

        $this->assertSame(1, $pageCount);
    }

    /**
     * Test creating thumbnails from valid images.
     *
     * @dataProvider validImagesProvider
     *
     * @param string $image
     */
    public function testCreateThumbnailFromImage($image)
    {
        $digitalObject = $this->newDigitalObject($image);

        $thumbnail = $digitalObject->createThumbnail();

        $this->assertInstanceOf(QubitDigitalObject::class, $thumbnail);
        $this->assertEquals(QubitTerm::THUMBNAIL_ID, $thumbnail->usageId);
        $this->assertEquals($digitalObject->id, $thumbnail->parentId);
        $this->assertEquals(QubitDigitalObject::THUMB_MIME_TYPE, $thumbnail->mimeType);
        $this->assertStringEndsWith('.'.QubitDigitalObject::THUMB_EXTENSION, $thumbnail->name);

        $originalImage = new Imagick();
        $originalImage->pingImage($image);

        $thumbImage = new Imagick();
        $thumbImage->pingImage($thumbnail->getAbsolutePath());

        // Image might not be resized if the width was already < 270
        $this->assertSame(min([270, $originalImage->getImageWidth()]), $thumbImage->getImageWidth());
        $this->assertLessThanOrEqual(1024, $thumbImage->getImageHeight());
    }

    /**
     * Paths to valid image files.
     */
    protected function validImagesProvider(): array
    {
        return [
            [__DIR__.'/../data/einstein.jpg'],
            [__DIR__.'/../data/gnome.png'],
            [__DIR__.'/../data/symfony.gif'],
        ];
    }

    /**
     * Test getting number of pages for pdfs.
     *
     * @dataProvider validPdfsProvider
     *
     * @param string $pdf
     * @param int    $pages
     */
    public function testGetPageCountPdf($pdf, $pages)
    {
        $digitalObject = $this->newDigitalObject($pdf);

        $pageCount = $digitalObject->getPageCount();

        $this->assertSame($pages, $pageCount);
    }

    /**
     * Test creating thumbnails from PDF files.
     *
     * @dataProvider validPdfsProvider
     *
     * @param mixed $pdf
     * @param mixed $pages
     */
    public function testCreateThumbnailFromPdf($pdf, $pages)
    {
        $digitalObject = $this->newDigitalObject($pdf);

        $thumbnail = $digitalObject->createThumbnail();

        $this->assertInstanceOf(QubitDigitalObject::class, $thumbnail);
        $this->assertEquals(QubitTerm::THUMBNAIL_ID, $thumbnail->usageId);
        $this->assertEquals($digitalObject->id, $thumbnail->parentId);
        $this->assertEquals(QubitDigitalObject::THUMB_MIME_TYPE, $thumbnail->mimeType);
        $this->assertStringEndsWith('.'.QubitDigitalObject::THUMB_EXTENSION, $thumbnail->name);

        $thumbImage = new Imagick();
        $thumbImage->pingImage($thumbnail->getAbsolutePath());

        $this->assertLessThanOrEqual(270, $thumbImage->getImageWidth());
        $this->assertLessThanOrEqual(1024, $thumbImage->getImageHeight());
    }

    /**
     * Paths to valid PDF files.
     */
    protected function validPdfsProvider(): array
    {
        return [
            [__DIR__.'/../data/test-1-page.pdf', 1],
            [__DIR__.'/../data/test-4-page.pdf', 4],
        ];
    }

    /**
     * Create a new digital object for the file at the path.
     *
     * @param mixed $filepath the file to create a digital object for
     *
     * @return QubitDigitalObject
     */
    protected function newDigitalObject($filepath): QubitDigitalObject
    {
        $testObject = new QubitObject();
        $testObject->save();

        $digitalObject = new QubitDigitalObject();
        $digitalObject->object = $testObject;
        $digitalObject->usageId = QubitTerm::MASTER_ID;
        $digitalObject->createDerivatives = false;
        $digitalObject->indexOnSave = false;
        $digitalObject->importFromFile($filepath);
        $digitalObject->save();

        return $digitalObject;
    }
}
