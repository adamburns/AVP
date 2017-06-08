Selectize.define('typing_mode', function(options) {
  if (this.settings.mode == 'multi') return; // Only works for single-select
  var self = this;

  this.setup = (function() {
    var original = self.setup;

    return function() {
      original.apply(this, arguments);

      this.on('dropdown_open', function() {
        self.typingValue = self.typingValue || self.getValue()
        var option = self.getOption(self.typingValue);

        self.$control_input.attr('placeholder', option.text().trim());
        self.$control_input.css({
          opacity: '1',
          width: '100%',
          position: 'relative'
        });
        self.$control.find('.item').hide();

        self.items = [];
        self.setCaret(0);
      });

      this.on('change', function() {
        self.typingValue = self.getValue();
      });

      this.$control_input.on('blur', function() {
        self.setValue(self.typingValue);
      });
    };
  })();
}); 
$(function () {
  $('[data-toggle="tooltip"]').tooltip();
  $('[data-toggle="confirmation"]').confirmation();
  $('select:not("no-selectize")').each(function() {
    if ($(this).val() == '__None' && $(this).find('option:selected').text() == '') {
      $(this).find('option[value="__None"]').remove();
      $(this).prepend('<option value="" disabled selected hidden>Select an option..</option>');
    }
  });
  $('select:not(".no-selectize, .selectize-create")').selectize({
    plugins: ['typing_mode'],
    selectOnTab: true
  });
  $('select.selectize-create').selectize({
    plugins: ['typing_mode'],
    selectOnTab: true,
    create: true
  });
});
$(".navbar-toggle").click(function(e) {
  e.preventDefault();
  $(".sidebar").toggleClass("nav-active");
  $("#main").toggleClass("nav-active");
  window.scrollTo(0,0);
});
$('form').submit(function() {
  $('#submit').parent().append("<span class='fa fa-circle-o-notch fa-spin fa-2x small-loader'></span>");
  $('input[type=submit]').attr('disabled', 'disabled');
});
$(document).ready(function() {
  outdatedBrowser({
    bgColor: '#f25648',
    color: '#ffffff',
    lowerThan: 'transform',
    languagePath: "/static/vendor/outdatedbrowser/outdatedbrowser.html"
  })
});
// Header shadow on scroll
$(window).scroll(function() {
  if ($(this).scrollTop() > 150 && $('.above-content').length) {
    $('.above-content').css('box-shadow', '0 4px 2px -2px #ccc');
  } else if ($(this).scrollTop() > 10 && !$('.above-content').length) {
    $('.nav-breadcrumb').css('box-shadow', '0 4px 2px -2px #ccc');
  } else {
    $('.nav-breadcrumb, .above-content').css('box-shadow', 'none');
  }
});
// Javascript to enable link to tab
var hash = document.location.hash;
var prefix = "tab_";
if (hash) {
  $('.nav-pills a[href='+hash.replace(prefix,"")+']').tab('show');
}
$('.nav-pills a').click(function (e) {
  $(this).tab('show');
  var scrollmem = $('body').scrollTop();
  window.location.hash = this.hash;
  $('html,body').scrollTop(scrollmem);
});
// Change hash for page-reload
$('.nav-pills a').on('shown', function (e) {
  window.location.hash = e.target.hash.replace("#", "#" + prefix);
});
function isIE(userAgent) {
  userAgent = userAgent || navigator.userAgent;
  return userAgent.indexOf("MSIE ") > -1 || userAgent.indexOf("Trident/") > -1;
}
// Override Fancybox loading animation
loadingExtension = {
  oldShowLoading: $.fancybox.showLoading,
  oldHideLoading: $.fancybox.hideLoading,
  showLoading: function () {
    H = $("html");
    W = $(window);
    D = $(document);
    F = $.fancybox;
    var el, viewport;

    F.hideLoading();
    el = $('<div id="fancybox-loading" class="animated fadeIn"><div><span class="fa-stack fa-lg"><i class="fa fa-circle-o-notch fa-spin fa-stack-2x"></i><i class="fa fa-file fa-stack-1x"></i></span><br/><p>Preparing your document...<br/><small class="text-muted">If you are having trouble, hit <strong>ESC</strong> to cancel, and <strong>Download</strong> instead</small></p></div></div>').click(F.cancel).appendTo('body');

    // If user will press the escape-button, the request will be canceled
    D.bind('keydown.loading', function (e) {
      if ((e.which || e.keyCode) === 27) {
        e.preventDefault();

        F.cancel();
      }
    });

    if (!F.defaults.fixed) {
      viewport = F.getViewport();

      el.css({
        position: 'absolute',
        top: (viewport.h * 0.5) + viewport.y,
        left: (viewport.w * 0.5) + viewport.x
      });
    }

    F.trigger('onLoading');
  },
  hideLoading: function () {
    $(document).unbind('.loading');
    $('#fancybox-loading').remove();
  }
};
$.extend($.fancybox, loadingExtension);
// Load fancyboxes
$(document).ready(function() {
  if (!isIE()) {
    $('.fb-document').fancybox({
      type: 'iframe',
      padding: 0,
      width: '95%',
      height: '95%',
      openEffect: 'none',
      closeEffect: 'none',
    });
  }
  $('.fb-image').fancybox({
    type: 'image',
    padding: 0
  });
  $('.fb-inline').fancybox({
    type: 'inline',
    padding: 0
  });
  $('.fb-iframe').fancybox({
    type: 'iframe',
    padding: 0,
    width: '95%',
    height: '95%',
    iframe: {
      scrolling: 'false'
    }
  });
});
// Cart management
$('.cart-button').click(function() {
  var cartButton = $(this);
  cartButton.prop('disabled', true);
  var document_id = cartButton.data('document');
  if (cartButton.hasClass('addtocart')) {
    $.getJSON('/user/_addtocart', {
      document_id: document_id,
    }, function(data) {
      var cartCount = parseInt($('#cart-count').text(), 10);
      $('#cart-count').html(++cartCount);
      cartButton.removeClass('addtocart btn-success');
      cartButton.addClass('removefromcart btn-danger');
      cartButton.html("<span class='fa fa-minus'></span> Remove from Cart");
      cartButton.prop('disabled', false);
      $.growl({
        title: "",
        message: "<strong>" + data.name + "</strong> added to cart.",
      },{
        type: "growl-success",
        delay: 3000,
        icon_type: 'class',
        placement: {
          from: "top",
          align: "center"
        },
        animate: {
          enter: 'animated fadeInDown',
          exit: 'animated fadeOutUp'
        },
      });
    });
  } else {
    $.getJSON('/user/_removefromcart', {
      document_id: document_id,
    }, function(data) {
      var cartCount = parseInt($('#cart-count').text(), 10);
      $('#cart-count').html(--cartCount);
      cartButton.removeClass('removefromcart btn-danger');
      cartButton.addClass('addtocart btn-success');
      cartButton.prop('disabled', false);
      cartButton.html("<span class='fa fa-cart-plus'></span> Add to Cart");
      $.growl({
        title: "",
        message: "<strong>" + data.name + "</strong> removed from cart.",
      },{
        type: "growl-success",
        delay: 3000,
        icon_type: 'class',
        placement: {
          from: "top",
          align: "center"
        },
        animate: {
          enter: 'animated fadeInDown',
          exit: 'animated fadeOutUp'
        },
      });
    });
  }
});

$('.clear-cart').click(function() {
  var clearButton = $(this);
  clearButton.prop('disabled', true);
  $.getJSON('/user/_clearcart', {
    // no data to send
  }, function(data) {
    location.reload();
  });
});
