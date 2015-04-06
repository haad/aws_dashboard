$(document).ready(function() {
    var table = $('#instances').DataTable();

    $('a.toggle-vis').on( 'click', function (e) {
        e.preventDefault();

        // Get the column API object
        var column = table.column( $(this).attr('data-column') );

        // Toggle the visibility
        column.visible( ! column.visible() );
    } );
} );

//$(document).ready(function() {
//    $('table.display').dataTable();
//} );
