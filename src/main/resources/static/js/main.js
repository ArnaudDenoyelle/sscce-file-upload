angular.module('sscce', ['ngRoute']).config(function ($routeProvider) {

      $routeProvider.when('/', {
        templateUrl: 'html/home.html',
        controller: 'home'
      }).when('/upload', {
        templateUrl: 'html/upload.html',
        controller: 'upload'
      })
    }
).controller('home', function ($scope, $http, $location) {
      $scope.login = function () {
        $http.post('/login', $.param($scope.user), {
          headers: {
            "content-type": "application/x-www-form-urlencoded"
          }
        }).success(function (data) {
          $location.path("upload")
        }).error(function (data) {
          console.log("error")
        })
      }
    }
).controller('upload', function ($http) {

    }
);
