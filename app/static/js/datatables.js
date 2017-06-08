$(document).ready(function() {
    $("table[id$='-table']").each(function(index) {
        var sortColumn = $(this).find(".sort-by").index();
        var sortDir = "desc";
        if ($(this).find(".sort-asc").length > 0)
            sortDir = "asc";
        var dataType = $(this).attr("id").split("-")[0];
        $(this).dataTable({
            "columnDefs": [
                { "targets": "no-sort", orderable: false }
            ],
            "order": [[ sortColumn, sortDir ]],
            "language": {
                "info": "Showing _START_ to _END_ of _TOTAL_ " + dataType,
                "infoEmpty": "No " + dataType + " available",
                "infoFiltered": "(filtered from _MAX_ " + dataType + ")",
                "lengthMenu": "Display _MENU_ " + dataType,
                "search": "",
                "searchPlaceholder": "Search...",
                "zeroRecords": "No " + dataType + " available"
            },
            "responsive": true,
            "lengthMenu": [ [15, 50, 100, -1], [15, 50, 100, "All"] ],
            {% if dashboard %}
            "paging": false,
            "ordering": false,
            "info": false,
            "filter": false
            {% endif %}
        });
        $("#" + dataType + "-wrapper").css("opacity", 1);
    });
    $(".loader").remove();
    $('.dataTables_wrapper').find('.dataTables_filter').append($('<span />', {
        'class': 'fa fa-close search-close close hidden'
    }));
    $('.search-close').click(function() {
        $('.dataTable').DataTable().search('').draw();
        $('input[type=search]').keyup();
    });
    $('.search-link').click(function() {
        var query = $(this).data('search');
        $('.dataTable').DataTable().search(query).draw();
        $('input[type=search]').keyup();
    });
    $('input[type=search]').keyup(function() {
        if ($(this).val()) {
            $(this).addClass('search-expanded');
            $('.search-close').removeClass('hidden');
        } else {
            $(this).removeClass('search-expanded');
            $('.search-close').addClass('hidden');
        }
    });
    $("tr").click(function() {
      $(this).parent().children().removeClass("selected");
        $(this).addClass("selected");
    });
});
$(document).on('mouseenter', "td", function() {
    var $this = $(this);
    if(this.offsetWidth < this.scrollWidth && !$this.attr('title')) {
        $this.tooltip({
            title: $this.text(),
            placement: "top",
            container: "body"
        });
        $this.tooltip('show');
    }
});
