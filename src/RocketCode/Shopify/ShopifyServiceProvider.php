<?php namespace RocketCode\Shopify;

use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\AliasLoader;

class ShopifyServiceProvider extends ServiceProvider
{

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->app->bind('ShopifyAPI', function($app, $config = FALSE)
		{
			return new API($config);
		});
	}

    public function boot()
    {
        $this->package('RocketCode/Shopify');
        AliasLoader::getInstance()->alias('ShopifyAPI', 'RocketCode\Shopify\API');
    }

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array();
	}

}
