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
azureSubscriptionChoiceMsg1 = Choisir Y traitera uniquement l'abonnement actuel dans le contexte connecté.
azureSubscriptionChoiceMsg2 = Choisir N vous demandera de choisir entre Tout ou une liste d'abonnements à traiter.
azureSubChoiceYN = Utiliser uniquement cet abonnement pour comparer les serveurs intégrés ? (Y/N)
azureSubChoiceAll = Traiter tous les abonnements (A) ou choisir des abonnements individuels (C)
azureSubChoiceNums = Fournir une liste de numéros d'abonnement séparés par des virgules (par exemple 1,3,4)
azureSubInvalidInput = Entrée invalide. Traitement de tous les abonnements associés.
processMachinesStart = Traitement (configuration ou lecture) de la configuration des prix pour la VM
processMachinesError = Échec de la récupération de la configuration des prix pour la VM
mdeGetMachinesTokenFailed = Échec de l'acquisition du jeton pour le point de terminaison MDE - Vérifiez l'enregistrement de l'application
mdeGetMachinesTokenSuccess = Récupération réussie du jeton de l'API Graph pour les machines MDE.
mdeGetMachinesFailed = Échec de la récupération des machines de Defender pour Endpoint
mainError = Une erreur s'est produite lors de l'exécution du script.
mainMidpointMessage = Traitement de Defender pour les serveurs terminé. Début du traitement de Defender pour Endpoint.
mainAzureMachinesCountMsg = Total Defender pour Serveurs serveurs inventoriés trouvés
mainMDETotalCount = Total Defender pour Endpoint appareils embarqués
mainMatchByIDMsg = Les appareils ont été appariés par ID de machine
mainMatchByNameMsg = Appareils appariés par nom
mainMDEUnmatchedMsg = Serveurs intégrés à MDE non présents dans l'inventaire de Defender pour Serveurs
mainMDCUnmatchedMsg = Serveurs dans l'inventaire de Defender pour Serveurs non intégrés à MDE
mainMDEComplete = Accès à la liste des appareils MDE terminé - Passage au processus de comparaison
mainNoCompareMsg = Aucune entrée dans la liste - aucune comparaison tentée
azureTShootMessage = Vérifiez la configuration d'intégration de Defender pour Cloud MDE
azureTShootURL = https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-defender-for-endpoint
mdeTShootMsg = Vérifiez la configuration d'intégration directe de MDE
mdeTShootURL = https://learn.microsoft.com/en-us/azure/defender-for-cloud/onboard-machines-with-defender-for-endpoint
NameMatchOnboardMessage = Serveurs embarqués ayant des noms correspondants
NameTShootMessage = Les serveurs disposent de toutes les fonctionnalités de Defender for Servers mais n'ont pas été intégrés par le service - Vérifiez la configuration d'intégration DFS
processNoRecordsMessage = Aucun problème trouvé
correctOnboardMessage = Serveurs correctement intégrés
correctOnboardTShootMsg = Les serveurs ont une fonctionnalité DFS complète avec un embarquement correct - Bien joué !
azureOnboardOnly = Serveurs intégrés uniquement à Defender pour serveurs (Azure)
mdeOnboardOnly = Serveurs intégrés uniquement à Defender pour Endpoint
'@