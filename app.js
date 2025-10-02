const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const fs = require('fs').promises;
const cookieParser = require('cookie-parser');
const session = require('express-session');
const { MongoClient, ObjectId } = require('mongodb');
const { body, validationResult } = require('express-validator'); // Adăugat pentru validare

const utilizatoriPath = path.join(__dirname, 'utilizatori.json');
let listaUtilizatori = [];

const mongoUrl = 'mongodb://localhost:27017';
const dbName = 'cumparaturi';

const MAX_FAILED_404_ATTEMPTS = 5; 
const BLOCK_DURATION_404_MS = 10 * 1000; 
const RESET_INTERVAL_404_MS = 10 * 60 * 1000; 

let failed404Attempts = {}; 
let blockedIPsFor404 = {};   

const MAX_LOGIN_ATTEMPTS_SHORT_TERM = 5;
const SHORT_TERM_LOCKOUT_DURATION_MS = 10 * 1000;
const LOGIN_ATTEMPT_WINDOW_MS = 10 * 1000;

let loginAttempts = {};

async function incarcaUtilizatori() {
    try {
        const data = await fs.readFile(utilizatoriPath, 'utf8');
        listaUtilizatori = JSON.parse(data);
    } catch (err) {
        console.error("Eroare la citirea utilizatorilor:", err);
        listaUtilizatori = [];
    }
}

let toateIntrebarile = {};
const jsonFilePath = path.join(__dirname, 'views/intrebari.json');

async function loadQuestions() {
    try {
        const data = await fs.readFile(jsonFilePath, 'utf8');
        toateIntrebarile = JSON.parse(data);
    } catch (err) {
        console.error("EROARE la citirea sau parsarea fișierului intrebari.json:", err);
        toateIntrebarile = { retro: [], moderne: [] };
    }
}

const app = express();
const port = 6789;

app.set('trust proxy', 1);

app.use(cookieParser());
app.use(session({
    secret: 'cheieSecreta123SuperPuternica!',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use((req, res, next) => {
    const ip = req.ip;
    if (blockedIPsFor404[ip] && blockedIPsFor404[ip] > Date.now()) {
        console.warn(`Acces blocat (404) pentru IP: ${ip}. Va fi deblocat la: ${new Date(blockedIPsFor404[ip]).toLocaleTimeString()}`);
        return res.status(403).render('ip_blocat', {
            titlu: 'Acces Blocat',
            ipBlocat: ip,
            timpDeblocare: new Date(blockedIPsFor404[ip]).toLocaleTimeString()
        });
    } else if (blockedIPsFor404[ip] && blockedIPsFor404[ip] <= Date.now()) {
        console.log(`IP-ul ${ip} (404) a fost deblocat automat.`);
        delete blockedIPsFor404[ip];
        delete failed404Attempts[ip];
    }
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(expressLayouts);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    res.locals.session = req.session;
    next();
});

function necesitaAutentificare(req, res, next) {
    if (req.session.utilizator) {
        next();
    } else {
        req.session.returnTo = req.originalUrl;
        req.session.mesajEroareAutentificare = "Trebuie să fii autentificat pentru a accesa această pagină.";
        res.redirect('/autentificare');
    }
}

function necesitaRolAdmin(req, res, next) {
    if (req.session.utilizator && req.session.utilizator.rol === 'ADMIN') {
        next();
    } else if (req.session.utilizator) {
        req.session.mesaj = "Acces interzis. Nu aveți drepturi de administrator.";
        res.status(403).redirect('/');
    } else {
        req.session.returnTo = req.originalUrl;
        req.session.mesajEroareAutentificare = "Trebuie să fii autentificat ca administrator.";
        res.redirect('/autentificare');
    }
}

(async () => {
    await incarcaUtilizatori();
    await loadQuestions();
    console.log("Utilizatorii și întrebările au fost încărcate. Serverul pornește...");

    app.get('/', async (req, res) => {
        if (req.session.utilizator && req.session.utilizator.rol === 'ADMIN' && req.query.autoproduse === 'true') {
            let client;
            try {
                client = new MongoClient(mongoUrl);
                await client.connect();
                const db = client.db(dbName);
                const produseCollection = db.collection('produse');
                const produse = await produseCollection.find({}).sort({_id: -1}).toArray();
                res.render('index', { 
                    titlu: 'Nou&Vechi - Admin View', 
                    produse: produse, 
                    afiseazaProduse: true,
                    originalUrl: req.originalUrl 
                });
            } catch (err) {
                console.error("Eroare la încărcarea automată a produselor pentru admin:", err);
                res.render('index', { 
                    titlu: 'Nou&Vechi', 
                    produse: [], 
                    afiseazaProduse: false,
                    originalUrl: req.originalUrl 
                });
            } finally {
                if (client) await client.close();
            }
        } else {
            res.render('index', { 
                titlu: 'Nou&Vechi', 
                produse: [], 
                afiseazaProduse: false,
                originalUrl: req.originalUrl 
            });
        }
    });

    app.get('/incarcare-bd', async (req, res) => {
        let client;
        try {
            client = new MongoClient(mongoUrl);
            await client.connect();
            const db = client.db(dbName);
            const produseCollection = db.collection('produse');
            const produse = await produseCollection.find({}).sort({_id: -1}).toArray();
            res.render('index', { 
                titlu: 'Nou&Vechi - Produse', 
                produse: produse, 
                afiseazaProduse: true,
                originalUrl: req.originalUrl
            });
        } catch (err) {
            console.error("Eroare la încărcarea din BD:", err);
            req.session.mesaj = "Eroare la încărcarea produselor din baza de date.";
            res.render('index', { 
                titlu: 'Eroare Produse', 
                produse: [], 
                afiseazaProduse: true,
                originalUrl: req.originalUrl
            });
        } finally {
            if (client) await client.close();
        }
    });

    app.post('/creare-bd', necesitaRolAdmin, async (req, res) => {
        let client;
        try {
            client = new MongoClient(mongoUrl);
            await client.connect();
            const db = client.db(dbName);
            await db.collection('produse').findOne({});
            req.session.mesaj = "Structura bazei de date este pregătită.";
            res.redirect('/incarcare-bd');
        } catch (err) {
            console.error("Eroare la verificarea BD:", err.message);
            req.session.mesaj = "Eroare la verificarea structurii bazei de date.";
            res.redirect('/incarcare-bd');
        } finally {
            if (client) await client.close();
        }
    });

    app.get('/inserarebd', necesitaRolAdmin, async (req, res) => {
        let client;
        try {
            client = new MongoClient(mongoUrl);
            await client.connect();
            const db = client.db(dbName);
            const produseCollection = db.collection('produse');
            const listaProduse = [
                                                { 
                                                    nume: "Televizor LG Smart", 
                                                    pret: 1250, 
                                                    imagine: "/images/products/tv_lg.png", 
                                                    specificatii: "Rezoluție 4K, HDR, WebOS" 
                                                },
                                                { 
                                                    nume: "Televizor Samsung QLED", 
                                                    pret: 1580, 
                                                    imagine: "/images/products/tv_samsung_generic.png", 
                                                    specificatii: "QLED, Ambient Mode, Tizen OS" 
                                                },
                                                { 
                                                    nume: "Televizor Philips Ambilight", 
                                                    pret: 1150, 
                                                    imagine: "/images/products/tv_philips_generic.png", 
                                                    specificatii: ["Ambilight 3 laturi", "Android TV", "P5 Engine"] 
                                                },
                                                { 
                                                    nume: "Televizor Sony Bravia", 
                                                    pret: 1820, 
                                                    imagine: "/images/products/tv_sony_generic.png", 
                                                    specificatii: "OLED, Acoustic Surface Audio, Google TV" 
                                                },
                                                { 
                                                    nume: "Televizor TCL Mini-LED", 
                                                    pret: 950, 
                                                    imagine: "/images/products/tv_tcl_generic.png", 
                                                    specificatii: "Mini-LED, Roku TV, Dolby Vision" 
                                                },
                                                { 
                                                    nume: "Televizor LG Golden Eye", 
                                                    pret: 350, 
                                                    imagine: "/images/products/tv_golden_eye.png", 
                                                    specificatii: "Afișaj CRT color, Funcție „Golden Eye” pentru reglarea automată a luminozității în funcție de lumina ambientală, Sunet stereo, Intrări AV (SCART, RCA), Telecomandă inclusă" 
                                                },
                                                { 
                                                    nume: "Televizor Sony Trinitron", 
                                                    pret: 150, 
                                                    imagine: "/images/products/tv_sony_vechi.png", 
                                                    specificatii: [
                                                    "Ecran CRT color",
                                                    "Tehnologie Trinitron",
                                                    "Intrare RF/AV",
                                                    "Sunet mono",
                                                    "Design retro"
                                                    ]
                                                },
                                                { 
                                                    nume: "Televizor Portabil Sport", 
                                                    pret: 150, 
                                                    imagine: "/images/products/tv_antena.png", 
                                                    specificatii: [
                                                    "Alb-negru",
                                                    "Produs de Întreprinderea Electronica București",
                                                    "Două tipuri de antene: simplă și dublă",
                                                    "Dimensiuni: 38 x 26 x 30 cm",
                                                    "Design portabil, carcasă robustă"
                                                ], 
                                                },
                                                { 
                                                    nume: "Televizor din comunism", 
                                                    pret: 150, 
                                                    imagine: "/images/products/tv_foarte_vechi.png", 
                                                     specificatii: [
                                                    "Alb-negru",
                                                    "Carcasă voluminoasă din lemn sau plastic dur",
                                                    "Produs în România în perioada comunistă",
                                                    "Comenzi mecanice și reglaje analogice",
                                                    "Necesită antenă externă",
                                                    "Design clasic cu butoane frontale"
                                                ] 
                                                },
];

            for (const produs of listaProduse) {
                await produseCollection.updateOne({ nume: produs.nume }, { $set: produs }, { upsert: true });
            }
            req.session.mesaj = "Produsele predefinite au fost inserate/actualizate.";
            res.redirect('/incarcare-bd');
        } catch (err) {
            console.error("Eroare la inserarea produselor predefinite:", err);
            req.session.mesaj = "Eroare la inserarea produselor predefinite.";
            res.redirect('/incarcare-bd');
        } finally {
            if (client) await client.close();
        }
    });
    
    app.post('/adaugare_cos', necesitaAutentificare, async (req, res) => {
        const idProdus = req.body.id;
        const refererUrl = req.headers.referer || '/incarcare-bd';
        if (!ObjectId.isValid(idProdus)) {
            req.session.mesaj = "ID produs invalid.";
            return res.redirect(refererUrl);
        }
        let client;
        try {
            client = new MongoClient(mongoUrl);
            await client.connect();
            const db = client.db(dbName);
            const produseCollection = db.collection('produse');
            const produs = await produseCollection.findOne({ _id: new ObjectId(idProdus) });
            if (!produs) {
                req.session.mesaj = "Produsul nu a fost găsit.";
                return res.redirect(refererUrl);
            }
            if (!req.session.cos) {
                req.session.cos = [];
            }
            const produsExistentIndex = req.session.cos.findIndex(item => item._id.toString() === produs._id.toString());
            if (produsExistentIndex > -1) {
                req.session.mesaj = `„${produs.nume}” este deja în coș.`;
            } else {
                req.session.cos.push(produs);
                req.session.mesaj = `Ai adăugat „${produs.nume}” în coș.`;
            }
            res.redirect(refererUrl);
        } catch (err) {
            console.error("Eroare la adăugarea în coș:", err);
            req.session.mesaj = "Eroare server la adăugarea în coș.";
            res.redirect(refererUrl);
        } finally {
            if (client) await client.close();
        }
    });

    app.get('/admin', necesitaRolAdmin, (req, res) => {
        const mesajAdmin = req.session.mesajAdmin;
        const tipMesajAdmin = req.session.tipMesajAdmin;
        const formData = req.session.formData;
        delete req.session.mesajAdmin;
        delete req.session.tipMesajAdmin;
        delete req.session.formData;
        res.render('admin_adauga_produs', { 
            titlu: 'Panou Administrare - Adaugă Produs',
            mesajAdmin: mesajAdmin,
            tipMesajAdmin: tipMesajAdmin,
            formData: formData || {}
        });
    });

    app.post('/admin/adauga-produs', 
        necesitaRolAdmin,
        [
            body('nume').trim().notEmpty().withMessage('Numele produsului este obligatoriu.').isLength({ max: 100 }).withMessage('Numele nu poate depăși 100 de caractere.'),
            body('pret').isFloat({ gt: 0 }).withMessage('Prețul trebuie să fie un număr pozitiv.'),
            body('categorie').trim().notEmpty().withMessage('Categoria este obligatorie.'),
            body('imagine').optional({ checkFalsy: true }).trim().isLength({ max: 255 }).withMessage('Calea imaginii este prea lungă.'),
            body('specificatii').optional({ checkFalsy: true }).trim().isLength({ max: 1000 }).withMessage('Specificațiile sunt prea lungi.')
        ],
        async (req, res) => {
            const errors = validationResult(req);
            const formData = req.body;

            if (!errors.isEmpty()) {
                req.session.mesajAdmin = errors.array().map(e => e.msg).join('<br>');
                req.session.tipMesajAdmin = "error";
                req.session.formData = formData;
                return res.redirect('/admin');
            }
            
            let client;
            try {
                const { nume, pret, imagine, specificatii, categorie } = formData; // Folosim formData validat (deși validarea e mai sus)
                const pretNumeric = parseFloat(pret); // Deja validat ca float > 0
                
                let specificatiiProcesate = "Nespecificat";
                if (specificatii && typeof specificatii === 'string' && specificatii.trim() !== '') {
                    const specArray = specificatii.split(',').map(s => s.trim()).filter(s => s !== '');
                    if (specArray.length > 1) {
                        specificatiiProcesate = specArray;
                    } else if (specArray.length === 1 && specArray[0] !== '') {
                        specificatiiProcesate = specArray[0];
                    }
                }
                const imagineProdus = (imagine && imagine.trim() !== '') ? imagine.trim() : '/images/products/default.png';
                const produsNou = {
                    nume: nume.trim(),
                    pret: pretNumeric,
                    imagine: imagineProdus,
                    specificatii: specificatiiProcesate,
                    categorie: categorie.trim()
                };
                client = new MongoClient(mongoUrl);
                await client.connect();
                const db = client.db(dbName);
                const produseCollection = db.collection('produse');
                const produsExistent = await produseCollection.findOne({ nume: produsNou.nume });
                if (produsExistent) {
                    req.session.mesajAdmin = `Un produs cu numele "${produsNou.nume}" există deja.`;
                    req.session.tipMesajAdmin = "error";
                    req.session.formData = formData;
                    return res.redirect('/admin');
                }
                await produseCollection.insertOne(produsNou);
                req.session.mesajAdmin = `Produsul "${produsNou.nume}" a fost adăugat cu succes!`;
                req.session.tipMesajAdmin = "success";
                res.redirect('/admin');
            } catch (err) {
                console.error("Eroare la adăugarea produsului:", err);
                req.session.mesajAdmin = "A apărut o eroare server la adăugarea produsului.";
                req.session.tipMesajAdmin = "error";
                req.session.formData = formData;
                res.redirect('/admin');
            } finally {
                if (client) await client.close();
            }
        }
    );
    
    app.get('/chestionar/:tip', (req, res) => {
        const tipChestionar = req.params.tip;
        const intrebariSelectate = toateIntrebarile[tipChestionar];
        if (!intrebariSelectate) {
            return res.status(404).send(`Tipul '${tipChestionar}' nu este valid.`);
        }
        const titluPagina = `Chestionar Televizoare ${tipChestionar.charAt(0).toUpperCase() + tipChestionar.slice(1)}`;
        const numeTema = `tema-${tipChestionar}`;
        res.render('chestionar', {
            titlu: titluPagina,
            intrebari: intrebariSelectate,
            tip: tipChestionar,
            tema: numeTema
        });
    });

    app.get('/autentificare', (req, res) => {
        const mesajSesiune = req.session.mesajEroareAutentificare || '';
        if (req.session.mesajEroareAutentificare) delete req.session.mesajEroareAutentificare;
        
        const ip = req.ip;
        if (loginAttempts[ip] && loginAttempts[ip].lockedUntil && loginAttempts[ip].lockedUntil > Date.now()) {
            const timeLeft = Math.ceil((loginAttempts[ip].lockedUntil - Date.now()) / 60000);
            return res.status(403).render('ip_blocat_login', {
                titlu: 'Acces Login Blocat',
                ipBlocat: ip,
                timpDeblocareMinute: timeLeft
            });
        }

        res.render('autentificare', {
            titlu: 'Autentificare Utilizator',
            mesajEroare: mesajSesiune
        });
    });

    app.post('/verificare-autentificare', async (req, res) => {
        const ip = req.ip;
        const { utilizator, parola } = req.body;

        if (loginAttempts[ip] && loginAttempts[ip].lockedUntil && loginAttempts[ip].lockedUntil > Date.now()) {
            const timeLeft = Math.ceil((loginAttempts[ip].lockedUntil - Date.now()) / 60000);
            req.session.mesajEroareAutentificare = `Prea multe încercări de login. Contul/IP-ul este blocat temporar. Încercați din nou în aproximativ ${timeLeft} minute.`;
            return res.redirect('/autentificare');
        } else if (loginAttempts[ip] && loginAttempts[ip].lockedUntil && loginAttempts[ip].lockedUntil <= Date.now()) {
            delete loginAttempts[ip];
        }

        const userGasit = listaUtilizatori.find(u => u.utilizator === utilizator && u.parola === parola);
        if (userGasit) {
            console.log(`Utilizatorul '${userGasit.utilizator}' (Rol: ${userGasit.rol}) autentificat cu succes de pe IP: ${ip}.`);
            delete loginAttempts[ip];
            const { parola: _, ...dateUtilizatorSesiune } = userGasit;
            req.session.utilizator = dateUtilizatorSesiune;
            let returnTo = req.session.returnTo || '/';
            if (userGasit.rol === 'ADMIN' && returnTo === '/') {
                returnTo = '/admin';
            }
            delete req.session.returnTo;
            res.redirect(returnTo);
        } else {
            if (!loginAttempts[ip]) {
                loginAttempts[ip] = { count: 0, firstAttemptTime: Date.now() };
            }
            if (Date.now() - loginAttempts[ip].firstAttemptTime > LOGIN_ATTEMPT_WINDOW_MS) {
                loginAttempts[ip] = { count: 0, firstAttemptTime: Date.now() };
            }
            loginAttempts[ip].count++;
            loginAttempts[ip].firstAttemptTime = Date.now();
            console.warn(`Login eșuat pentru utilizatorul '${utilizator}' de pe IP: ${ip}. Încercarea #${loginAttempts[ip].count}.`);
            if (loginAttempts[ip].count >= MAX_LOGIN_ATTEMPTS_SHORT_TERM) {
                loginAttempts[ip].lockedUntil = Date.now() + SHORT_TERM_LOCKOUT_DURATION_MS;
                const lockDurationMinutes = SHORT_TERM_LOCKOUT_DURATION_MS / 60000;
                console.warn(`IP-ul ${ip} (sau utilizatorul '${utilizator}') a fost blocat de la login pentru ${lockDurationMinutes} minute.`);
                req.session.mesajEroareAutentificare = `Prea multe încercări de login. Contul/IP-ul a fost blocat temporar pentru ${lockDurationMinutes} minute.`;
            } else {
                req.session.mesajEroareAutentificare = 'Utilizator sau parolă incorectă!';
            }
            res.redirect('/autentificare');
        }
    });

    app.get('/delogare', (req, res) => {
        req.session.destroy(err => {
            if (err) {
                console.error("Eroare la delogare:", err);
                return res.status(500).send("Eroare la delogare");
            }
            res.redirect('/');
        });
    });

    app.post('/rezultat-chestionar', (req, res) => {
        const raspunsuriUtilizator = req.body;
        const tipChestionar = raspunsuriUtilizator.tip_chestionar;
        const intrebariCorecte = toateIntrebarile[tipChestionar];
        if (!tipChestionar || !intrebariCorecte || intrebariCorecte.length === 0) {
            return res.status(400).send('Datele sunt invalide.');
        }
        let scor = 0;
        intrebariCorecte.forEach((intrebare, index) => {
            const numeInput = `raspuns_q${index}`;
            if (raspunsuriUtilizator[numeInput] === intrebare.corect) {
                scor++;
            }
        });
        const titluPagina = `Rezultat Chestionar ${tipChestionar.charAt(0).toUpperCase() + tipChestionar.slice(1)}`;
        const numeTema = `tema-${tipChestionar}`;
        res.render('rezultat', {
            titlu: titluPagina,
            scor,
            totalIntrebari: intrebariCorecte.length,
            tip: tipChestionar,
            tema: numeTema
        });
    });

    app.use((req, res, next) => {
        const ip = req.ip;
        if (!failed404Attempts[ip]) {
            failed404Attempts[ip] = { count: 0, firstAttemptTime: Date.now() };
        }
        if (Date.now() - failed404Attempts[ip].firstAttemptTime > RESET_INTERVAL_404_MS) {
            failed404Attempts[ip] = { count: 0, firstAttemptTime: Date.now() };
        }
        failed404Attempts[ip].count++;
        failed404Attempts[ip].firstAttemptTime = Date.now();
        console.log(`Încercare eșuată (404) de la IP: ${ip}. URL: ${req.originalUrl}. Nr. încercări: ${failed404Attempts[ip].count}`);
        if (failed404Attempts[ip].count >= MAX_FAILED_404_ATTEMPTS) {
            blockedIPsFor404[ip] = Date.now() + BLOCK_DURATION_404_MS;
            console.warn(`IP-ul ${ip} blocat (404) pentru ${BLOCK_DURATION_404_MS / 60000} min.`);
        }
        res.status(404).render('404', { titlu: 'Resursă Negăsită', urlCeruta: req.originalUrl });
    });

    app.use((err, req, res, next) => {
        console.error("EROARE SERVER NEPRINSĂ:", err.message, err.stack);
        res.status(err.status || 500).render('eroare_server', { 
            titlu: 'Eroare Server', 
            mesajEroare: err.message,
        });
    });

    app.listen(port, () => {
        console.log(`Serverul rulează la http://localhost:${port}`);
    });

})();