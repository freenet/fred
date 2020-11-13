// @license magnet:?xt=urn:btih:1f739d935676111cfff4b4693e3816e664797050&dn=gpl-3.0.txt GPL-v3-or-Later
function checkAll(bx, classname) {
  var matching = document.getElementsByClassName(classname);
  for (var matchingElement of matching) {
    var inputTags = matchingElement.getElementsByTagName('input');
    for (var i of inputTags) {
      if (i.type === 'checkbox') {
        i.checked = bx.checked;
      }
    }
  }
}
// @license-end
