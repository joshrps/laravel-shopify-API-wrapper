Laravel / Shopify API Wrapper
===========================

An easy-to-use PHP package to communicate with [Shopify's API](http://docs.shopify.com/api) in Laravel.

## Installation

#### Require rocket-code/shopify in `composer.json`

Add `"rocket-code/shopify"` in your "require" object. With a blank Laravel install, it will look something like this:

For Laravel 5, use `"rocket-code/shopify":"~2.0"`. For Laravel 4, use `"rocket-code/shopify":"~1.0"`.

```
	"require": {
		"laravel/framework": "4.2.*",
		"rocket-code/shopify": "~1.0"
	}
```

#### Add the Service Provider

In `app/config/app.php`, add `RocketCode\Shopify\ShopifyServiceProvider` to the end of the `providers` array.

## Setting Up

To begin, use `App::make()` to grab an instance of the `API` class.

```
$sh = App::make('ShopifyAPI');
```

#### Loading API Credentials

Simply pass an array with the following keys (and filled-in values) to prepare. Not all values need to be passed at once; you can call the `setup()` method as many times as you'd like; it will only accept the following 4 keys, and overwrite a values if it's already set.

```
$sh->setup(['API_KEY' => '', 'API_SECRET' => '', 'SHOP_DOMAIN' => '', 'ACCESS_TOKEN' => '']);
```

##### Shortcut:

Pass the setup array as the second argument in `App::make()`:

```
$sh = App::make('ShopifyAPI', ['API_KEY' => '', 'API_SECRET' => '', 'SHOP_DOMAIN' => '', 'ACCESS_TOKEN' => '']);
```

That's it! You're ready to make some API calls.

## Finding the Install URL

After setting up with at least `SHOP_DOMAIN` & `API_KEY`, call `installURL()` with an array of permissions ([the app's Scope](docs.shopify.com/api/authentication/oauth#scopes)):

```
$sh->installURL(['permissions' => array('write_orders', 'write_products')]);
```

You may also pass a redirect URL per the `redirect_uri` parameter [as described by the Shopify API Docs](http://docs.shopify.com/api/authentication/oauth#asking-for-permission)

```
$sh->installURL(['permissions' => array('write_orders', 'write_products'), 'redirect' => 'http://myapp.com/success']);
```

## Authentication / Getting OAuth Access Token

In order to make Authenticated requests, [the Access Token must be passed as a header in each request](http://docs.shopify.com/api/authentication/oauth#making-authenticated-requests). This package will automatically do that for you, but you must first authenticate your app on each store (as the user installs it), and save the Access Token.

Once the user accesses the Install URL and clicks the Install button, they will be redirected back to your app with data in the Query String.

After setting up with at least `SHOP_DOMAIN`, `API_KEY`, & `API_SECRET`, call `getAccessToken()` with the code passed back in the URL. Laravel makes this easy:

```
$code = Input::get('code');
$sh = App::make('ShopifyAPI', ['API_KEY' => '', 'API_SECRET' => '', 'SHOP_DOMAIN' => '']);

try
{
	$accessToken = $sh->getAccessToken($code);
}
catch (Exception $e)
{
	echo '<pre>Error: ' . $e->getMessage() . '</pre>';
}

// Save $accessToken
```

#### Verifying OAuth Data

Shopify returns a hashed value to validate the data against. To validate (recommended before calling `getAccessToken()`), utilize `verifyRequest()`.

```
try
{
	$verify = $sh->verifyRequest(Input::all());
	if ($verify)
	{
		$code = Input::get('code');
		$accessToken = $sh->getAccessToken($code);
	}
	else
	{
		// Issue with data
	}

}
catch (Exception $e)
{
	echo '<pre>Error: ' . $e->getMessage() . '</pre>';
}


	
```

`verifyRequest()` returns `TRUE` when data is valid, otherwise `FALSE`. It throws an Exception in two cases: If the timestamp generated by Shopify and your server are more than an hour apart, or if the argument passed is not an array or URL-encoded string of key/values.

If you would like to skip the timestamp check (not recommended unless you cannot correct your server's time), you can pass `TRUE` as a second argument to `verifyRequest()` and timestamps will be ignored:

```
$verify = $sh->verifyRequest(Input::all(), TRUE);
```

## Private Apps
The API Wrapper does not distinguish between private and public apps. In order to utilize it with a private app, set up everything as you normally would, replacing the OAuth Access Token with the private app's Password.

## Calling the API

Once set up, simply pass the data you need to the `call()` method.

```
$result = $sh->call($args);
```

#### `call()` Parameters

The parameters listed below allow you to set required values for an API call as well as override additional default values.

* `METHOD`: The HTTP method to use for your API call. Different endpoints require different methods.
  * Default: `GET`
* `URL`: The URL of the API Endpoint to call.
  * Default: `/` (not an actual endpoint)
* `HEADERS`: An array of additional Headers to be sent
  * Default: Empty `array()`. Headers that are automatically sent include:
    * Accept 
    * Content-Type
    * charset
    * X-Shopify-Access-Token
* `CHARSET`: Change the charset if necessary
  * Default: `UTF-8`
* `DATA`: An array of data being sent with the call. For example, `$args['DATA'] = array('product' => $product);` For an [`/admin/products.json`](http://docs.shopify.com/api/product#create) product creation `POST`.
  * Default: Empty `array()`
* `RETURNARRAY`: Set this to `TRUE` to return data in `array()` format. `FALSE` will return a `stdClass` object.
  * Default: `FALSE`
* `ALLDATA`: Set this to `TRUE` if you would like all error and cURL info returned along with your API data (good for debugging). Data will be available in `$result->_ERROR` and `$result->_INFO`, or `$result['_ERROR']` and `$result['_INFO']`, depending if you are having it returned as an object or array. Recommended to be set to `FALSE` in production.
  * Default: `FALSE`
* `FAILONERROR`: The value passed to cURL's [CURLOPT_FAILONERROR](http://php.net/manual/en/function.curl-setopt.php) setting. `TRUE` will cause the API Wrapper to throw an Exception if the HTTP code is >= `400`. `FALSE` in combination with `ALLDATA` set to `TRUE` will give you more debug information.
  * Default: `TRUE`


## Some Examples

Assume that `$sh` has already been set up as documented above.

#### Listing Products

```
try
{

	$call = $sh->call(['URL' => 'products.json', 'METHOD' => 'GET', 'DATA' => ['limit' => 5, 'published_status' => 'any']]);
}
catch (Exception $e)
{
	$call = $e->getMessage();
}

echo '<pre>';
var_dump($call);
echo '</pre>';

```

`$call` will either contain a `stdClass` object with `products` or an Exception error message.

#### Creating a snippet from a Laravel View

```
$testData = ['name' => 'Foo', 'location' => 'Bar'];
$view = (string) View::make('snippet', $testData);

$themeID = 12345678;

try
{
	$call = $sh->call(['URL' => '/admin/themes/' . $themeID . '/assets.json', 'METHOD' => 'PUT', 'DATA' => ['asset' => ['key' => 'snippets/test.liquid', 'value' => $view] ] ]);
}
catch (Exception $e)
{
	$call = $e->getMessage();
}

echo '<pre>';
var_dump($call);
echo '</pre>';
```

#### Performing operations on multiple shops

The `setup()` method makes changing the current shop simple.

```
$apiKey = '123';
$apiSecret = '456';

$sh = App::make('ShopifyAPI', ['API_KEY' => $apiKey, 'API_SECRET' => $apiSecret]);

$shops = array(
		'my-shop.myshopify.com'		=> 'abc',
		'your-shop.myshopify.com'	=> 'def',
		'another.myshopify.com'		=> 'ghi'
		);
		
foreach($shops as $domain => $access)
{
	$sh->setup(['SHOP_DOMAIN' => $domain, 'ACCESS_TOKEN'' => $access]);
	// $sh->call(), etc

}

```


