<?php

use PHPUnit\Framework\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class QubitRequireLoginTest extends TestCase
{
    protected $contextMock;
    protected $filter;

    protected function setUp(): void
    {
        $configurationClass = 'qubitConfiguration';
        if (!class_exists($configurationClass)) {
            $this->markTestSkipped("The application configuration class '{$configurationClass}' does not exist.");
        }

        // Create an instance of the application configuration
        $configuration = new $configurationClass('test', false);

        // Create a sfContext instance
        $this->contextMock = sfContext::createInstance($configuration);

        // The login module is "user" by default
        sfConfig::set('sf_login_module', 'user');

        // Create the filter instance and pass the sfContext
        $this->filter = new QubitRequireLoginFilter($this->contextMock);
    }

    public function testLoginActionIsAuthRoute()
    {
        $this->assertTrue($this->filter->isAuthRoute('user', 'login'));
    }

    public function testLogoutActionIsAuthRoute()
    {
        $this->assertTrue($this->filter->isAuthRoute('user', 'logout'));
    }

    public function testOidcModuleIsAuthRoute()
    {
        $this->assertTrue($this->filter->isAuthRoute('oidc', 'login'));
        $this->assertTrue($this->filter->isAuthRoute('oidc', 'logout'));
    }

    public function testCasModuleIsAuthRoute()
    {
        $this->assertTrue($this->filter->isAuthRoute('cas', 'login'));
        $this->assertTrue($this->filter->isAuthRoute('cas', 'logout'));
    }

    public function testNonAuthUserActionIsNotAuthRoute()
    {
        $this->assertFalse($this->filter->isAuthRoute('user', 'list'));
        $this->assertFalse($this->filter->isAuthRoute('user', 'index'));
    }

    public function testBrowsingRoutesAreNotAuthRoutes()
    {
        $this->assertFalse($this->filter->isAuthRoute('informationobject', 'browse'));
        $this->assertFalse($this->filter->isAuthRoute('staticpage', 'index'));
    }
}
