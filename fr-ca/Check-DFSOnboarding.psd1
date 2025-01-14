ConvertFrom-StringData @'
moduleCheckInstalled = Vérification si le module est installé :
moduleInstalled = Module installé
moduleNotInstalled = Module non installé. Installation en cours
moduleError = Veuillez vous assurer que les modules suivants sont installés
azureConnectLoginRequired = Connexion Azure requise. Veuillez vérifier la fenêtre de connexion sur votre bureau
azureConnectTokenSuccess = Jeton Azure récupéré avec succès
azureConnectTokenFailed = Impossible d'acquérir le jeton d'accès. Fermeture
azureSubscriptionsStart = Récupération des abonnements Azure
azureSubscriptionException = Une exception s'est produite lors de la récupération des abonnements Azure
azureSubscriptionContextNotFound = Contexte Azure non trouvé
azureSubscriptionContextFound = Contexte Azure trouvé
azureSubscriptionNotFound = Impossible de trouver un abonnement Azure avec le compte connecté
azureResourceGroupsStart = Récupération des groupes de ressources pour l'abonnement :
azureResourceGroupNotFound = Impossible de récupérer les ressources du groupe de ressources
azureGetVirtualMachinesFailed = Échec de la récupération des machines virtuelles
azureGetVirtualMachineScaleSetsFailed = Échec de la récupération des ensembles de machines virtuelles
azureGetArcMachinesFailed = Échec de la récupération des machines Arc
processMachinesStart = Traitement (configuration ou lecture) de la configuration des prix pour la VM
processMachinesError = Échec de la récupération de la configuration des prix pour la VM
mdeGetMachinesTokenFailed = Échec de l'acquisition du jeton pour le point de terminaison MDE - Vérifiez l'enregistrement de l'application
mdeGetMachinesTokenSuccess = Récupération réussie du jeton de l'API Graph pour les machines MDE.
mdeGetMachinesFailed = Échec de la récupération des machines de Defender pour Endpoint
mainError = Une erreur s'est produite lors de l'exécution du script.
mainMidpointMessage = Traitement de Defender pour les serveurs terminé. Début du traitement de Defender pour Endpoint.
'@