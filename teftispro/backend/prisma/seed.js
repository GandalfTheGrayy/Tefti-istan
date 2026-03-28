// TeftişPro - Seed Data
// Varsayılan kullanıcılar ve örnek veriler

const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
    console.log('🌱 Seed verileri oluşturuluyor...');

    // Rolleri oluştur
    const roles = ['admin', 'planlamacı', 'field', 'gözden_geçiren', 'firma_sahibi', 'sube_kullanici'];

    for (const roleName of roles) {
        await prisma.role.upsert({
            where: { name: roleName },
            update: {},
            create: { name: roleName }
        });
    }
    console.log('✅ Roller oluşturuldu');

    // Rolleri al
    const adminRole = await prisma.role.findUnique({ where: { name: 'admin' } });
    const planlamaciRole = await prisma.role.findUnique({ where: { name: 'planlamacı' } });
    const fieldRole = await prisma.role.findUnique({ where: { name: 'field' } });
    const gozdenGecirenRole = await prisma.role.findUnique({ where: { name: 'gözden_geçiren' } });
    const firmaSahibiRole = await prisma.role.findUnique({ where: { name: 'firma_sahibi' } });
    const subeKullaniciRole = await prisma.role.findUnique({ where: { name: 'sube_kullanici' } });

    // Kullanıcıları oluştur (ad soyad formatında)
    const users = [
        { name: 'Ali Yılmaz', email: 'admin@admin.com', password: '!Admin123456', roleId: adminRole.id },
        { name: 'Ayşe Demir', email: 'planlama@demo.local', password: '!Plan12345!!', roleId: planlamaciRole.id },
        { name: 'Mehmet Kaya', email: 'saha@demo.local', password: '!Field1234!!', roleId: fieldRole.id },
        { name: 'Fatma Özkan', email: 'onay@demo.local', password: '!Onay12345!!', roleId: gozdenGecirenRole.id },
        { name: 'Mustafa Çelik', email: 'firma@demo.local', password: '!Firma1234!!', roleId: firmaSahibiRole.id },
        { name: 'Hasan Demir', email: 'firma@hdiskender.local', password: '!Firma1234!!', roleId: firmaSahibiRole.id },
        { name: 'Zeynep Arslan', email: 'sube@hdiskender.local', password: '!Sube12345!!', roleId: subeKullaniciRole.id }
    ];

    for (const userData of users) {
        const hashedPassword = await bcrypt.hash(userData.password, 10);
        await prisma.user.upsert({
            where: { email: userData.email },
            update: { name: userData.name },
            create: {
                name: userData.name,
                email: userData.email,
                password: hashedPassword,
                roleId: userData.roleId
            }
        });
    }
    console.log('✅ Kullanıcılar oluşturuldu');

    // Örnek şirket oluştur
    const company = await prisma.company.upsert({
        where: { name: 'Demo Holding A.Ş.' },
        update: {},
        create: { name: 'Demo Holding A.Ş.' }
    });
    console.log('✅ Şirket oluşturuldu');

    // Örnek bölge oluştur
    const region = await prisma.region.upsert({
        where: { name_companyId: { name: 'Marmara Bölgesi', companyId: company.id } },
        update: {},
        create: {
            name: 'Marmara Bölgesi',
            companyId: company.id
        }
    });
    console.log('✅ Bölge oluşturuldu');

    // Örnek şubeler oluştur
    const branches = [
        { name: 'Kadıköy Şubesi', city: 'İstanbul', regionId: region.id, companyId: company.id },
        { name: 'Beşiktaş Şubesi', city: 'İstanbul', regionId: region.id, companyId: company.id },
        { name: 'Bursa Merkez Şubesi', city: 'Bursa', regionId: region.id, companyId: company.id }
    ];

    for (const branchData of branches) {
        await prisma.branch.upsert({
            where: { id: -1 }, // Upsert için geçici - her zaman create yapacak
            update: {},
            create: branchData
        });
    }
    // Şubeleri kontrol et ve eksikse oluştur
    for (const branchData of branches) {
        const existing = await prisma.branch.findFirst({
            where: { name: branchData.name, companyId: branchData.companyId }
        });
        if (!existing) {
            await prisma.branch.create({ data: branchData });
        }
    }
    console.log('✅ Şubeler oluşturuldu');

    // Örnek kategoriler ve sorular oluştur
    const categories = [
        {
            title: 'Genel Temizlik',
            questions: [
                { text: 'Zemin temizliği yeterli mi?', points: 5, noteRequired: false },
                { text: 'Cam ve aynalar temiz mi?', points: 5, noteRequired: false },
                { text: 'Çöp kutuları düzenli boşaltılıyor mu?', points: 5, noteRequired: false },
                { text: 'Tuvalet ve lavabolar hijyenik mi?', points: 10, noteRequired: true },
                { text: 'Havalandırma yeterli mi?', points: 5, noteRequired: false }
            ]
        },
        {
            title: 'Yangın Güvenliği',
            questions: [
                { text: 'Yangın söndürücüler yerinde mi?', points: 10, noteRequired: true },
                { text: 'Yangın söndürücülerin son kontrolü yapılmış mı?', points: 10, noteRequired: true },
                { text: 'Acil çıkış yolları açık mı?', points: 10, noteRequired: true },
                { text: 'Yangın alarm sistemi çalışıyor mu?', points: 10, noteRequired: true },
                { text: 'Acil durum planı asılı mı?', points: 5, noteRequired: false }
            ]
        },
        {
            title: 'İş Sağlığı ve Güvenliği',
            questions: [
                { text: 'Çalışanlar kişisel koruyucu ekipman kullanıyor mu?', points: 10, noteRequired: true },
                { text: 'İlk yardım dolabı mevcut ve dolu mu?', points: 10, noteRequired: true },
                { text: 'Tehlike uyarı işaretleri yerinde mi?', points: 5, noteRequired: false },
                { text: 'Elektrik panoları güvenli mi?', points: 10, noteRequired: true },
                { text: 'Ergonomik çalışma koşulları sağlanıyor mu?', points: 5, noteRequired: false }
            ]
        },
        {
            title: 'Müşteri Deneyimi',
            questions: [
                { text: 'Personel kıyafetleri uygun mu?', points: 5, noteRequired: false },
                { text: 'Müşteri karşılama alanı düzenli mi?', points: 5, noteRequired: false },
                { text: 'Ürün sergileme standartlara uygun mu?', points: 5, noteRequired: false },
                { text: 'Fiyat etiketleri doğru ve görünür mü?', points: 5, noteRequired: false },
                { text: 'Kasa alanı düzenli mi?', points: 5, noteRequired: false }
            ]
        },
        {
            title: 'Depo ve Stok Yönetimi',
            questions: [
                { text: 'Depo alanı düzenli mi?', points: 5, noteRequired: false },
                { text: 'Ürünler doğru şekilde istifleniyor mu?', points: 5, noteRequired: false },
                { text: 'Son kullanma tarihleri kontrol ediliyor mu?', points: 10, noteRequired: true },
                { text: 'Soğuk zincir ürünleri uygun sıcaklıkta mı?', points: 10, noteRequired: true },
                { text: 'Stok sayımları düzenli yapılıyor mu?', points: 5, noteRequired: false }
            ]
        }
    ];

    for (const categoryData of categories) {
        let category = await prisma.category.findFirst({
            where: { title: categoryData.title }
        });

        if (!category) {
            category = await prisma.category.create({
                data: { title: categoryData.title }
            });
        }

        for (const questionData of categoryData.questions) {
            const existingQuestion = await prisma.question.findFirst({
                where: { text: questionData.text, categoryId: category.id }
            });

            if (!existingQuestion) {
                await prisma.question.create({
                    data: {
                        ...questionData,
                        categoryId: category.id
                    }
                });
            }
        }
    }
    console.log('✅ Kategoriler ve sorular oluşturuldu');

    // Saha kullanıcısına şube ataması yap
    const fieldUser = await prisma.user.findUnique({ where: { email: 'saha@demo.local' } });
    const kadikoyBranch = await prisma.branch.findFirst({ where: { name: 'Kadıköy Şubesi' } });

    if (fieldUser && kadikoyBranch) {
        const existingAssignment = await prisma.branchAssignment.findFirst({
            where: { userId: fieldUser.id, branchId: kadikoyBranch.id }
        });

        if (!existingAssignment) {
            await prisma.branchAssignment.create({
                data: { userId: fieldUser.id, branchId: kadikoyBranch.id }
            });
        }
    }
    console.log('✅ Şube ataması yapıldı');

    // Firma sahibine şirket ata
    const firmaUser = await prisma.user.findUnique({ where: { email: 'firma@demo.local' } });
    if (firmaUser) {
        await prisma.user.update({
            where: { id: firmaUser.id },
            data: { companyId: company.id }
        });
        await prisma.company.update({
            where: { id: company.id },
            data: { ownerId: firmaUser.id }
        });
    }
    console.log('✅ Firma sahibi atandı');

    // HD İskender şirketi oluştur
    const hdIskender = await prisma.company.upsert({
        where: { name: 'HD İskender' },
        update: {},
        create: { name: 'HD İskender' }
    });
    console.log('✅ HD İskender şirketi oluşturuldu');

    // HD İskender bölgesi
    const hdRegion = await prisma.region.upsert({
        where: { name_companyId: { name: 'İstanbul Bölgesi', companyId: hdIskender.id } },
        update: {},
        create: {
            name: 'İstanbul Bölgesi',
            companyId: hdIskender.id
        }
    });

    // HD İskender şubesi
    let hdBranch = await prisma.branch.findFirst({
        where: { name: 'HD İskender Şube', companyId: hdIskender.id }
    });
    if (!hdBranch) {
        hdBranch = await prisma.branch.create({
            data: {
                name: 'HD İskender Şube',
                city: 'İstanbul',
                companyId: hdIskender.id,
                regionId: hdRegion.id
            }
        });
    }
    console.log('✅ HD İskender şubesi oluşturuldu');

    // HD İskender kullanıcılarına şirket/şube ata
    const hdFirmaUser = await prisma.user.findUnique({ where: { email: 'firma@hdiskender.local' } });
    if (hdFirmaUser) {
        await prisma.user.update({
            where: { id: hdFirmaUser.id },
            data: { companyId: hdIskender.id }
        });
        await prisma.company.update({
            where: { id: hdIskender.id },
            data: { ownerId: hdFirmaUser.id }
        });
    }

    const subeUser = await prisma.user.findUnique({ where: { email: 'sube@hdiskender.local' } });
    if (subeUser && hdBranch) {
        await prisma.user.update({
            where: { id: subeUser.id },
            data: { companyId: hdIskender.id, branchId: hdBranch.id }
        });
    }
    console.log('✅ HD İskender kullanıcıları atandı');

    console.log('🎉 Seed verileri başarıyla oluşturuldu!');
    console.log('\n📋 Giriş bilgileri:');
    console.log('  admin@admin.com / !Admin123456');
    console.log('  planlama@demo.local / !Plan12345!!');
    console.log('  saha@demo.local / !Field1234!!');
    console.log('  onay@demo.local / !Onay12345!!');
    console.log('  firma@demo.local / !Firma1234!!');
    console.log('  firma@hdiskender.local / !Firma1234!!');
    console.log('  sube@hdiskender.local / !Sube12345!!');
}

main()
    .catch((e) => {
        console.error('Seed hatası:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
