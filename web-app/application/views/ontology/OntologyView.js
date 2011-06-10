/**
 * Created by IntelliJ IDEA.
 * User: lrollus
 * Date: 7/04/11
 * Time: 10:12
 * To change this template use File | Settings | File Templates.
 */
var OntologyView = Backbone.View.extend({
    tagName : "div",
    self : this,
    alreadyBuild : false,
    $tabsOntologies : null,
    ontologiesPanel : null,
    idOntology : null,
    addOntologyDialog : null,
       events: {
          "click .addOntology": "showAddOntologyPanel"
       },
    initialize: function(options) {
        this.container = options.container;
        this.idOntology = options.idOntology;
        this.idTerm =  options.idTerm;
    },
    refresh : function() {
        var self = this;
        window.app.models.ontologies.fetch({
            success : function (collection, response) {
                self.render();
            }});
    },
    refresh : function(idOntology) {
        var self = this;
        this.idOntology = idOntology;
        window.app.models.ontologies.fetch({
            success : function (collection, response) {
                self.render();
            }});
    },
    select : function(idOntology) {
        var self = this;
        console.log("refreshAndSelect:"+idOntology);
        this.idOntology = idOntology;
        self.render();
    },
    render : function () {
        var self = this;
        require([
            "text!application/templates/ontology/OntologyList.tpl.html"
        ],
               function(tpl) {
                   self.doLayout(tpl);
               });

        return this;
    },
    doLayout: function(tpl) {
        console.log("OntologyView.render");

        var self = this;
        $(this.el).html(_.template(tpl, {}));

        self.$tabsOntologies = $(self.el).find("#tabsontology");
           $(self.el).find(".addOntology").button({
                 icons : {secondary: "ui-icon-plus" }
              });
        self.initOntologyTabs();

        return this;
    },
       showAddOntologyPanel : function() {
          console.log("OntologySearchPanel: showAddOntologyPanel");
          var self = this;
          $('#addontology').remove();
          self.addOntologyDialog = new AddOntologyDialog({ontologiesPanel:self,el:self.el}).render();
       },
    select : function(idOntology,idTerm) {
        console.log("select ontology " + idOntology + " term " + idTerm);
        var self = this;
        //select ontology
        var selectedOntologyIndex = 0;
        var index = 0;
        self.model.each(function(ontology) {
            //get index of selected ontology
            if(idOntology== ontology.get("id")) {
                selectedOntologyIndex = index;
            }
            index = index + 1;
        });
        self.ontologiesPanel[selectedOntologyIndex].selectTerm(idTerm);
        console.log("activate = " + selectedOntologyIndex);
        self.$tabsOntologies.accordion( "activate" , selectedOntologyIndex );
    },
    /**
     * Init annotation tabs
     */
    initOntologyTabs : function(){
        var self = this;
        require(["text!application/templates/ontology/OntologyTab.tpl.html", "text!application/templates/ontology/OntologyTabContent.tpl.html"], function(ontologyTabTpl, ontologyTabContentTpl) {
            console.log("OntologyView: initOntologyTabs");
            console.log("OntologyView: initOntologyTabs create "+ self.model.length);
            self.ontologiesPanel = new Array();
            //add "All annotation from all term" tab
            var selectedOntologyIndex = 0;
            var index = 0;
            self.model.each(function(ontology) {
                //add x term tab
                self.addOntologyToTab(ontologyTabTpl, ontologyTabContentTpl, { id : ontology.get("id"), name : ontology.get("name")});
                //create project search panel
                var view = new OntologyPanelView({
                    model : ontology,
                    el:$(self.el).find("#tabsontology-"+ontology.id),
                    container : self,
                    ontologiesPanel : self
                });
                view.render();
                self.ontologiesPanel.push(view);
                //get index of selected ontology
                if(self.idOntology== ontology.get("id")) {
                    selectedOntologyIndex = index;
                }
                index = index + 1;
            });
            //self.fetchOntologies();
            console.log(self.$tabsOntologies);


            if(!self.alreadyBuild)
                self.$tabsOntologies.accordion();
            console.log("activate = " + selectedOntologyIndex);
            self.$tabsOntologies.accordion( "activate" , selectedOntologyIndex );
             $(".accordeonOntology").css("height", "auto");
            self.ontologiesPanel[selectedOntologyIndex].selectTerm(self.idTerm);
        });
    },
    /**
     * Add the the tab with ontology info
     * @param id  ontology id
     * @param name ontology name
     */
    addOntologyToTab : function(ontologyTabTpl, ontologyTabContentTpl, data) {
        this.$tabsOntologies.append("<h3><a id=\"ontologyTitle"+ data.id+"\" href=\"#\">"+data.name+"</a></h3>");
        this.$tabsOntologies.append(_.template(ontologyTabContentTpl, data));
        //tabs;
        /*         $("#ultabsontology").append(_.template(ontologyTabTpl, data));
         $("#listtabontology").append(_.template(ontologyTabContentTpl, data)); */
    }
});