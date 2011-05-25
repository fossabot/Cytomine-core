var ExplorerTabs = Backbone.View.extend({
       tagName : "div",
       tabs : [], //that we are browsing
       /**
        * ExplorerTabs constructor
        * @param options
        */
       initialize: function(options) {
          this.container = options.container
       },
       /**
        * Grab the layout and call ask for render
        */
       render : function() {
          var self = this;
          require(["text!application/templates/explorer/Tabs.tpl.html"], function(tpl) {
             self.doLayout(tpl);
          });
          return this;
       },
       /**
        * Render the html into the DOM element associated to the view
        * @param tpl
        */
       doLayout: function(tpl) {
          var self = this;
          $(this.el).html(_.template(tpl, {}));
          var tabs = $(this.el).children('.tabs');
          var height = 0;
          tabs.tabs({
                 add: function(event, ui) {
                    console.log("select tabs " + ui.panel.id);
                    $("#"+ui.panel.id).parent().parent().css('height', "100%");
                    if (ui.panel.id != "tabs-0") { //tab is not the dashboard
                       $("#"+ui.panel.id).attr('style', 'width:100%;height:100%;');
                       $("a[href=#"+ui.panel.id+"]").parent().append("<span class='ui-icon ui-icon-close'>Remove Tab</span>");
                       $("a[href=#"+ui.panel.id+"]").parent().find("span.ui-icon-close" ).click(function() {
                          var index = $( "li", tabs ).index( $( this ).parent() );
                          self.removeTab(index);
                       });
                    }
                    tabs.tabs('select', '#' + ui.panel.id);
                 },
                 show: function(event, ui){
                    $("#"+ui.panel.id).attr('style', 'width:100%;height:100%;overflow:auto');
                    return true;
                 },
                 select: function(event, ui) {
                    if (ui.panel.id == "tabs-0") { //tab is  the dashboard
                       self.refreshDashboard();
                    }
                    return true;
                 }
              });

          $("ul.tabs a").css('height', $("ul.tabs").height())
          return this;
       },
       /**
        *  Add a Tab containing a BrowseImageView instance
        *  @idImage : the id of the Image we want to display
        *  @options : some init options we want to pass the the BrowseImageView Instance
        */
       addBrowseImageView : function(idImage, options) {
          var self = this;
          var alreadyOpened = _.detect(self.tabs, function(object) {
             return object.idImage == idImage;
          });
          if (alreadyOpened) {
             alreadyOpened.view.initOptions = options;
             return;
          }

          var tabs = $(self.el).children('.tabs');
          var view = new BrowseImageView({
                 model : window.app.models.imagesinstance.get(idImage),
                 initOptions : options,
                 el: tabs
              }).render();
          self.tabs.push({
                 idImage : idImage,
                 view : view
              });

       },
       /**
        * Return the reference to a BrowseImageView instance
        * contained in a tab
        * @param idImage the ID of an Image contained in a BrowseImageView
        */
       getBrowseImageView : function(idImage) {
          var tab  = _.detect(this.tabs, function(object) {
             console.log("looking for tab " + idImage  + " vs " + object.idImage);
             return object.idImage == idImage;
          });
          return tab.view != null ? tab.view : null;
       },
       /**
        * Remove a Tab
        * @param index the identifier of the Tab
        */
       removeTab : function (index) {
          this.tabs.splice(index,1);
          var tabs = $(this.el).children('.tabs');
          tabs.tabs( "remove", index);

       },
       /**
        * Show a tab
        * @param index the identifier of the Tab
        */
       showTab : function(index) {
          var image = _.detect(this.tabs, function(object) {
             return object.idImage == index;
          });
          image.view.show();
          var tabs = $(this.el).children('.tabs');
          tabs.tabs('select', '#tabs-' + index);

       },
       /**
        * Return the number of opened tabs
        */
       size : function() {
          return _.size(this.tabs);
       },
       /**
        * Close all the Tabs
        */
       closeAll : function() {
          console.log("close all");
          var self = this;
          while (this.size() > 0) {
             self.removeTab(0);
          }
          $(self.el).hide();
          $(self.el).parent().find('.noProject').show();
       },
       /**
        * Add a ProjectDashBoardView instance in the first Tab
        * @param dashboard the ProjectDashBoardView instance
        */
       addDashboard : function(dashboard) {
          console.log("add dashboard");
          var tabs = $(this.el).children('.tabs');
          tabs.tabs("add", "#tabs-0", 'Dashboard');
          $("#explorer > .browser").show();
          $("#explorer > .noProject").hide();
          this.tabs.push({
                 idImage : 0,
                 view : dashboard
              });
       },
       /**
        * Ask to the dashboard view to refresh
        */
       refreshDashboard : function () {
          var dashboardTab = _.detect(this.tabs, function(object) {
             console.log("looking for db :" + object.idImage);
             return object.idImage == 0;
          });
          console.log("refresh db...");
          dashboardTab.view.refresh();
       }
    });