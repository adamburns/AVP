from flask.ext.assets import Bundle, Environment
from .. import app

bundles = {
    'home_js': Bundle(
        'vendor/jquery/js/jquery-2.1.4.min.js',
        'vendor/bootstrap/js/bootstrap.min.js',
        'vendor/bootstrap-growl/js/bootstrap-growl.min.js',
        'vendor/outdatedbrowser/js/outdatedbrowser.min.js',
        'vendor/retina/js/retina.min.js',
        'vendor/selectize/js/selectize.min.js',
        output='gen/home.%(version)s.js'
    ),
    'home_css': Bundle(
        'vendor/bootstrap/css/bootstrap.min.css',
        'vendor/font-awesome/css/font-awesome.min.css',
        'vendor/animate/css/animate.min.css',
        'vendor/outdatedbrowser/css/outdatedbrowser.min.css',
        Bundle('vendor/selectize/css/selectize.css',
               'vendor/selectize/css/selectize.bootstrap3.css',
               Bundle('css/common.scss',
                      filters='scss'
               ),
               filters='cssmin'
        ),
        output='gen/home.%(version)s.css'
    ),
    'panel_js': Bundle(
        'vendor/jquery/js/jquery-2.1.4.min.js',
        'vendor/bootstrap/js/bootstrap.min.js',
        'vendor/bootstrap-growl/js/bootstrap-growl.min.js',
        'vendor/outdatedbrowser/js/outdatedbrowser.min.js',
        'vendor/retina/js/retina.min.js',
        'vendor/fancybox/js/fancybox.min.js',
        'vendor/mediaelement/mediaelement-and-player.min.js',
        'vendor/selectize/js/selectize.min.js',
        'vendor/chart/js/chart.min.js',
        'vendor/datatables/js/datatables.min.js',
        Bundle('vendor/bootstrap-confirmation/js/bootstrap-confirmation.js',
               'js/checked-list-box.js',
               'js/panel.js',
               filters='jsmin'
        ),
        output='gen/panel.%(version)s.js'
    ),
    'panel_css': Bundle(
        'vendor/bootstrap/css/bootstrap.min.css',
        'vendor/font-awesome/css/font-awesome.min.css',
        'vendor/animate/css/animate.min.css',
        'vendor/fancybox/css/fancybox.css',
        'vendor/mediaelement/mediaelementplayer.min.css',
        'vendor/outdatedbrowser/css/outdatedbrowser.min.css',
        'vendor/datatables/css/datatables.min.css',
        Bundle('vendor/selectize/css/selectize.css',
               'vendor/selectize/css/selectize.bootstrap3.css',
               Bundle('css/common.scss',
                      'css/panel.scss',
                      filters='scss'
               ),
               filters='cssmin'
        ),
        output='gen/panel.%(version)s.css'
    ),
    'email_css': Bundle(
        Bundle('css/email.scss',
                filters='scss'
               ),
        output='../templates/email/gen/email.css'
    )
}

assets = Environment(app)

assets.register(bundles)
