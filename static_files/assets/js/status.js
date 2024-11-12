$(document).ready(function () {
        
    $.fn.editableform.buttons =
    '<button type="submit" class="btn btn-primary btn-sm editable-submit p-2">' +
    '<i class="fa fa-fw fa-check"></i>' +
    '</button>' +
    '<button type="button" class="btn btn-warning btn-sm editable-cancel p-2">' +
    '<i class="fa fa-fw fa-times"></i>' +
    '</button>';
    $('.xedit').editable({
        url: '{% url "change_status" %}',
        prepend:'{{file.Status}}',

        mode: 'inline',
        inputclass:"form-select form-select-sm",
        params: {
            csrfmiddlewaretoken:'{{csrf_token}}',
            model:'models.Task'
        },
        source:[
        {value:'Not_Started',text:"Not_Started"},
        {value:'On_Progress',text:"On_Progress"}],
        display:function(t,e){
            var n=$.grep(e,
            function(e){return e.value==t});
            n.length?$(this).text(n[0].text).css("color",
            {"Not_Started":"red","On_Progress":"blue","completed":"green"}[t]):$(this).empty()},

        success: function (response, newValue) {
            console.log('Updated Successfully', newValue);
        }
    });
});