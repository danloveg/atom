(function () {

  'use strict';

  var angular = require('angular');

  require('../../vendor/angular-ui.js');

 /*
   * Module definition
   */

  angular.module('momaApp', [

    require('./services').name,
    require('./directives').name,
    require('./controllers').name,
    require('./filters').name,

    'ui.router',
    'ui.bootstrap'

  ]);
  /*
   * Configuration constants
   */

  angular.module('momaApp')
    .constant('ATOM_CONFIG', {

      // Base path, e.g. "/~user/atom"
      basePath: Qubit.relativeUrlRoot,

      // Frontend path, e.g. "/~user/atom/index.php"
      frontendPath: Qubit.frontend,

      // DRMC path, e.g. "/~user/atom/index.php/drmc"
      DRMCPath: Qubit.frontend + 'drmc/',

      // Views, assets, etc...
      viewsPath: Qubit.relativeUrlRoot + '/plugins/arDrmcPlugin/frontend/app/views',
      assetsPath: Qubit.relativeUrlRoot + '/plugins/arDrmcPlugin/frontend/assets'

    });


  /*
   * Kickstart the application
   *
   * This is executed after all the services have been configured and the injector
   * has been created.
   */

  angular.module('momaApp')
    .run(function ($rootScope, $state, $stateParams, ATOM_CONFIG) {

      // Add references to $state and $stateParams to the $rootScope so we can
      // access from them from our entire application
      $rootScope.$state = $state;
      $rootScope.$stateParams = $stateParams;

      // Same here
      $rootScope.basePath = ATOM_CONFIG.basePath;
      $rootScope.viewsPath = ATOM_CONFIG.viewsPath;
      $rootScope.assetsPath = ATOM_CONFIG.assetsPath;

      $rootScope.headerPartialPath = ATOM_CONFIG.viewsPath + '/partials/header.html';
      $rootScope.footerPartialPath = ATOM_CONFIG.viewsPath + '/partials/footer.html';

    });


  /*
   * Routing
   */

  angular.module('momaApp')
    .config(function ($locationProvider, $stateProvider, $urlRouterProvider, ATOM_CONFIG) {

      // Use HTML5 mode
      $locationProvider.html5Mode(true);
      $locationProvider.hashPrefix('!');

      // Default route
      $urlRouterProvider.otherwise(ATOM_CONFIG.DRMCPath + 'dashboard');

      // Define ui-router states
      $stateProvider

        // Dashboard
        .state('dashboard', {
          url: ATOM_CONFIG.DRMCPath + 'dashboard',
          controller: 'DashboardCtrl',
          templateUrl: ATOM_CONFIG.viewsPath + '/dashboard.html'
        })

        // AIPs
        .state('aips', {
          abstract: true,
          url: ATOM_CONFIG.DRMCPath + 'aips',
          template: '<ui-view/>'
        })
        .state('aips.browser', {
          url: '',
          controller: 'AIPBrowserCtrl',
          templateUrl: ATOM_CONFIG.viewsPath + '/aips.browser.html'
        })
        .state('aips.view', {
          url: '/{id:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}}',
          controller: 'AIPViewCtrl',
          templateUrl: ATOM_CONFIG.viewsPath + '/aips.view.html'
        })

        // Works
        .state('works', {
          abstract: true,
          url: ATOM_CONFIG.DRMCPath + 'works',
          template: '<ui-view/>'
        })
        .state('works.browser', {
          url: '',
          controller: 'WorkBrowserCtrl',
          templateUrl: ATOM_CONFIG.viewsPath + '/works.browser.html'
        })
        .state('works.view', {
          url: '/{id}',
          controller: 'WorkViewCtrl',
          templateUrl: ATOM_CONFIG.viewsPath + '/works.view.html'
        })

        // Technology Records
        .state('technology-records', {
          abstract: true,
          url: ATOM_CONFIG.DRMCPath + 'technology-records',
          template: '<ui-view/>'
        })
        .state('technology-records.browser', {
          url: '',
          controller: 'TechnologyRecordBrowserCtrl',
          templateUrl: ATOM_CONFIG.viewsPath + '/technology-records.browser.html'
        })
        .state('technology-records.view', {
          url: '/{id}',
          controller: 'TechnologyRecordViewCtrl',
          templateUrl: ATOM_CONFIG.viewsPath + '/technology-records.view.html'
        });

    });

})();
